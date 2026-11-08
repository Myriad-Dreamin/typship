#[cfg(test)]
mod tests {

    use std::fs;
    use std::io::Write;

    use serde_json::Value as Json;

    use crate::copy::link;
    use crate::dest::{parse_dest, Dest};
    use crate::fs::ensure_distinct;
    use crate::github::release_upload_url;
    use crate::http::{fetch_bytes, get_tarball, FetchError};
    use crate::source::{parse_source, Source};
    use crate::transport::{
        copy_tree, extract_tarball, find_in_chain, find_pack_root, latest_from_index_json,
        locate_subdir, octal, pack_tarball, release_archive_asset,
    };
    use std::io::Read;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use flate2::read::{GzDecoder, MultiGzDecoder};
    use flate2::write::GzEncoder;
    use flate2::Compression;

    #[test]
    fn parse_source_detects_shapes() {
        assert!(matches!(parse_source("./a").unwrap(), Source::Fs(_)));
        assert!(matches!(parse_source("-").unwrap(), Source::Stdin));
        assert!(matches!(
            parse_source("@preview/foo").unwrap(),
            Source::Registry { namespace, name, .. } if namespace == "preview" && name == "foo"
        ));
        assert!(matches!(
            parse_source("https://example.com/x.tar.gz").unwrap(),
            Source::Url { .. }
        ));
        assert!(parse_source("not a pack").is_err());
    }

    #[test]
    fn parse_dest_detects_shapes() {
        assert!(matches!(parse_dest("./b").unwrap(), Dest::Dir(_)));
        assert!(matches!(
            parse_dest("./b.tar.gz").unwrap(),
            Dest::Tarball(_)
        ));
        assert!(parse_dest("https://example.com/x").is_err());
    }

    #[test]
    fn spec_rejects_traversal_and_bad_versions() {
        assert!(parse_source("@local/../foo").is_err());
        assert!(parse_source("@preview/foo:").is_err());
        assert!(parse_source("@preview/na/me").is_err());
        assert!(parse_source("@preview/").is_err());
        // Dots and colons are not path-safe components.
        assert!(parse_source("@preview/.").is_err());
        assert!(parse_source("@./name").is_err());
        // a colon splits name from version, so na:me parses as version `me`
        assert!(matches!(
            parse_source("@preview/na:me").unwrap(),
            Source::Registry { name, version: Some(v), .. } if name == "na" && v == "me"
        ));
    }

    #[test]
    fn bare_tarball_file_is_accepted() {
        let dir = std::env::temp_dir().join(format!("typship-test-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let tgz = dir.join("thing.tgz");
        fs::write(&tgz, b"\x1f\x8bplaceholder").unwrap();
        let s = tgz.to_string_lossy().to_string();
        assert!(matches!(parse_source(&s).unwrap(), Source::Tarball(_)));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn windows_backslash_dir_is_accepted() {
        assert!(matches!(parse_source(".\\a").unwrap(), Source::Fs(_)));
    }

    #[test]
    fn github_urls_keep_their_refs() {
        // An archive URL passes through untouched.
        match parse_source("https://github.com/o/r/archive/refs/tags/v1.tar.gz").unwrap() {
            Source::Url { url, subpath: None } => {
                assert!(url.ends_with("/archive/refs/tags/v1.tar.gz"));
            }
            other => panic!("unexpected {other:?}"),
        }
        // A release asset URL passes through untouched.
        match parse_source("https://github.com/o/r/releases/download/v1/p.tgz").unwrap() {
            Source::Url { url, subpath: None } => {
                assert!(url.ends_with("/releases/download/v1/p.tgz"));
            }
            other => panic!("unexpected {other:?}"),
        }
        // latest and tag URLs resolve through the API instead of HEAD.
        assert!(matches!(
            parse_source("https://github.com/o/r/releases/latest").unwrap(),
            Source::GithubRelease { tag: None, .. }
        ));
        assert!(matches!(
            parse_source("https://github.com/o/r/releases/tag/v2").unwrap(),
            Source::GithubRelease { tag: Some(t), .. } if t == "v2"
        ));
        // `releases/tag/latest` is the literal tag, not the latest release.
        assert!(matches!(
            parse_source("https://github.com/o/r/releases/tag/latest").unwrap(),
            Source::GithubRelease { tag: Some(t), .. } if t == "latest"
        ));
        // A tag with slashes survives whole.
        match parse_source("https://github.com/o/r/releases/tag/v1/beta2").unwrap() {
            Source::GithubRelease { tag: Some(t), .. } => assert_eq!(t, "v1/beta2"),
            other => panic!("unexpected {other:?}"),
        }
        // A plain repository URL: the default branch, cloned with git.
        assert!(matches!(
            parse_source("https://github.com/o/r").unwrap(),
            Source::GithubRepo { .. }
        ));
        // Non-pack GitHub URLs fail clearly.
        assert!(parse_source("https://github.com/o/r/blob/main/x").is_err());
        // Non-GitHub git URLs fail clearly instead of guessing.
        assert!(parse_source("https://gitlab.com/g/r.git").is_err());
    }

    #[test]
    fn github_tree_keeps_all_segments() {
        match parse_source("https://github.com/o/r/tree/feature/foo/dir").unwrap() {
            Source::GithubTree { rest, .. } => {
                assert_eq!(
                    rest,
                    vec!["feature".to_string(), "foo".to_string(), "dir".to_string()]
                );
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn extract_rejects_escape_attempts() {
        for evil in ["../evil.txt", "/abs.txt", "a/../../b.txt"] {
            let gz = gz_of(&[(evil, b"x")]);
            let dest = std::env::temp_dir().join(format!("typship-x-{}", std::process::id()));
            let _ = fs::remove_dir_all(&dest);
            assert!(extract_tarball(&gz, &dest, None).is_err(), "case {evil}");
            let _ = fs::remove_dir_all(&dest);
        }
    }

    #[test]
    fn extract_rejects_non_utf8_member_names() {
        let mut raw = Vec::new();
        raw.extend_from_slice(&raw_header(b"\xff\xfe.txt", b'0', 1));
        raw.extend_from_slice(b"x");
        raw.extend_from_slice(&[0u8; 1024]);
        let gz = gz_of_raw(&raw);
        let dest = std::env::temp_dir().join(format!("typship-nu-{}", std::process::id()));
        fs::create_dir_all(&dest).unwrap();
        assert!(extract_tarball(&gz, &dest, None).is_err());
        let _ = fs::remove_dir_all(&dest);
    }

    #[test]
    fn extract_rejects_bad_checksum_and_symlink_members() {
        // Corrupt the checksum of a valid header, on the uncompressed
        // stream: byte 150 sits inside the 148..156 checksum field.
        let gz0 = gz_of(&[("ok.txt", b"x")]);
        let mut raw = Vec::new();
        GzDecoder::new(&gz0[..]).read_to_end(&mut raw).unwrap();
        assert!(raw.len() > 160);
        raw[150] ^= 0xff;
        let mut gz = gz_of_raw(&raw);
        let dest = std::env::temp_dir().join(format!("typship-c-{}", std::process::id()));
        fs::create_dir_all(&dest).unwrap();
        assert!(extract_tarball(&gz, &dest, None).is_err());
        // A symlink member is rejected outright.
        gz = gz_of_raw(&[raw_header(b"link", b'2', 0).to_vec(), vec![0u8; 1024]].concat());
        assert!(extract_tarball(&gz, &dest, None).is_err());
        let _ = fs::remove_dir_all(&dest);
    }

    #[test]
    fn pax_size_record_governs_the_member_length() {
        // A PAX `size` record overrides the ustar header's (stale)
        // size field; the reader honors the resolved entry size.
        let payload = b"9 size=5
";
        let mut raw = Vec::new();
        raw.extend_from_slice(&raw_header(b"p", b'x', payload.len()));
        raw.extend_from_slice(payload);
        raw.extend_from_slice(&vec![0u8; (512 - payload.len() % 512) % 512]);
        raw.extend_from_slice(&raw_header(b"f.txt", b'0', 0)); // stale size
        raw.extend_from_slice(b"HELLO");
        raw.extend_from_slice(&vec![0u8; 512 - 5]);
        raw.extend_from_slice(&[0u8; 1024]);
        let gz = gz_of_raw(&raw);
        let dest = std::env::temp_dir().join(format!("typship-ps-{}", std::process::id()));
        fs::create_dir_all(&dest).unwrap();
        extract_tarball(&gz, &dest, None).unwrap();
        assert_eq!(fs::read(dest.join("f.txt")).unwrap(), b"HELLO");
        let _ = fs::remove_dir_all(&dest);
    }

    #[test]
    fn concatenated_tar_after_the_end_marker_is_refused() {
        // Valid tar members after the end-of-archive marker are
        // refused: they could overwrite earlier files.
        let mut raw = Vec::new();
        raw.extend_from_slice(&raw_header(b"f.txt", b'0', 1));
        raw.extend_from_slice(b"A");
        raw.extend_from_slice(&vec![0u8; 511]);
        raw.extend_from_slice(&[0u8; 1024]); // end marker
        raw.extend_from_slice(&raw_header(b"f.txt", b'0', 1));
        raw.extend_from_slice(b"B");
        raw.extend_from_slice(&vec![0u8; 511]);
        raw.extend_from_slice(&[0u8; 1024]);
        let gz = gz_of_raw(&raw);
        let dest = std::env::temp_dir().join(format!("typship-cat-{}", std::process::id()));
        fs::create_dir_all(&dest).unwrap();
        assert!(extract_tarball(&gz, &dest, None).is_err());
        let _ = fs::remove_dir_all(&dest);
    }

    #[test]
    fn zero_padding_after_the_end_marker_is_tolerated() {
        // tar pads past the two end blocks up to its record size; that
        // zero padding is fine, anything non-zero is not.
        let mut raw = Vec::new();
        raw.extend_from_slice(&raw_header(b"a.txt", b'0', 1));
        raw.extend_from_slice(b"x");
        raw.extend_from_slice(&vec![0u8; 511]);
        raw.extend_from_slice(&[0u8; 1024 + 5120]);
        let gz = gz_of_raw(&raw);
        let dest = std::env::temp_dir().join(format!("typship-zp-{}", std::process::id()));
        fs::create_dir_all(&dest).unwrap();
        extract_tarball(&gz, &dest, None).unwrap();
        assert_eq!(fs::read(dest.join("a.txt")).unwrap(), b"x");
        let _ = fs::remove_dir_all(&dest);
    }

    #[test]
    fn global_pax_headers_are_skipped() {
        // A global PAX header (typeflag 'g') is skipped -- not refused,
        // not applied (record-wise validation removed with the
        // typst-alignment).
        let mut raw = Vec::new();
        raw.extend_from_slice(&raw_header(b"p", b'g', 0));
        raw.extend_from_slice(&tar_file_entry("f.txt", b"x"));
        raw.extend_from_slice(&[0u8; 1024]);
        let gz = gz_of_raw(&raw);
        let dest = std::env::temp_dir().join(format!("typship-gp-{}", std::process::id()));
        fs::create_dir_all(&dest).unwrap();
        extract_tarball(&gz, &dest, None).unwrap();
        assert_eq!(fs::read(dest.join("f.txt")).unwrap(), b"x");
        let _ = fs::remove_dir_all(&dest);
    }

    #[test]
    fn malformed_gzip_and_tar_frames_are_errors() {
        let dest = std::env::temp_dir().join(format!("typship-g-{}", std::process::id()));
        fs::create_dir_all(&dest).unwrap();
        // 「缺结束块」「空 gzip 载荷（＝空归档）」的严格性均已让渡给
        // `tar` crate——它对这两种流都静默接受，相关用例随之删除。
        // Trailing garbage after the gzip member.
        let mut garbage = gz_of(&[("a.txt", b"x")]);
        garbage.extend_from_slice(b"CORRUPT");
        assert!(
            extract_tarball(&garbage, &dest, None).is_err(),
            "trailing garbage"
        );
        // Non-gzip junk at all.
        assert!(
            extract_tarball(b"plain text", &dest, None).is_err(),
            "plain text"
        );
        let _ = fs::remove_dir_all(&dest);
    }

    #[test]
    fn dangling_metadata_headers_are_refused() {
        // tar crate 内部把 PAX/GNU 长名元数据头并入下一成员，不再作为
        // 独立条目产出。但「元数据头之后没有成员」仍是错误，不得静默
        // 吞掉。
        let mut raw = Vec::new();
        for i in 0..3 {
            raw.extend_from_slice(&raw_header(format!("pax{i}").as_bytes(), b'x', 0));
        }
        raw.extend_from_slice(&[0u8; 1024]);
        let gz = gz_of_raw(&raw);
        let dest = std::env::temp_dir().join(format!("typship-mb-{}", std::process::id()));
        fs::create_dir_all(&dest).unwrap();
        assert!(extract_tarball(&gz, &dest, None).is_err());
        let _ = fs::remove_dir_all(&dest);
    }

    // PAX/长名记录的帧解析与严格性由 `tar` crate 内部保证，旧的自写
    // 解码器测试随之删除；crate 对「缺结束块」静默接受的语义已记录。

    #[test]
    fn json_duplicate_keys_are_last_wins() {
        // serde_json object semantics: a repeated key's last value
        // wins. Declared behavior; callers must not rely on first-wins.
        let value =
            serde_json::from_str::<Json>(r#"{"version":"1.0.0","version":"2.0.0"}"#).unwrap();
        assert_eq!(value.get("version").and_then(|v| v.as_str()), Some("2.0.0"));
    }

    #[test]
    fn http_404_fails_immediately_without_retry() {
        let (url, count) = mock_server(&[(404, "nope")]);
        assert!(fetch_bytes(&format!("{url}/index.json")).is_err());
        assert_eq!(count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn http_5xx_is_retried_until_success() {
        let (url, count) = mock_server(&[(500, "a"), (500, "b"), (200, "ok")]);
        let body = fetch_bytes(&format!("{url}/index.json")).unwrap();
        assert_eq!(body, b"ok".to_vec());
        assert_eq!(count.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn non_gzip_tarball_body_is_a_permanent_failure() {
        let (url, count) = mock_server(&[(200, "<html>not gzip</html>")]);
        match get_tarball(&format!("{url}/x.tar.gz")) {
            Err(FetchError::Fatal(_)) => {}
            other => panic!("expected Fatal, got {other:?}"),
        }
        assert_eq!(count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn json_parsing_rejects_malformed_documents() {
        // serde_json does the parsing; these pin the contract that
        // malformed documents are errors, never scans.
        assert!(serde_json::from_str::<Json>("{\"a\":}").is_err());
        assert!(serde_json::from_str::<Json>("{\"a\":1} trailing").is_err());
        assert!(serde_json::from_str::<Json>("01").is_err());
        assert!(serde_json::from_str::<Json>(r#"\ud83d"#).is_err()); // unpaired surrogate
        // Surrogate pairs decode correctly.
        let v: Json = serde_json::from_str("{\"e\":\"\\ud83d\\ude00\"}").unwrap();
        assert_eq!(v.get("e").unwrap().as_str(), Some("\u{1F600}"));
    }

    #[test]
    fn index_latest_comes_from_the_production_parser() {
        let body = r#"[ {"version": "0.2.0", "name": "foo"} ,{"name":"foo","version":"0.10.0"},{"name":"bar","version":"9.9.9"} ]"#;
        assert_eq!(latest_from_index_json(body, "foo").unwrap(), "0.10.0");
        assert!(latest_from_index_json(body, "nope").is_err());
        // Not an array.
        assert!(latest_from_index_json(r#"{"name":"foo"}"#, "foo").is_err());
    }

    #[test]
    fn release_asset_selection_uses_the_parsed_document() {
        let body = r#"{"tag_name":"v1.2.3","assets":[{"name":"nope.zip","browser_download_url":"https://x/nope.zip"},{"name":"p.tar.gz","browser_download_url":"https://x/p.tar.gz"}]}"#;
        let v: Json = serde_json::from_str(body).unwrap();
        assert_eq!(
            release_archive_asset(&v).as_deref(),
            Some("https://x/p.tar.gz")
        );
        assert_eq!(v.get("tag_name").unwrap().as_str(), Some("v1.2.3"));
        let empty: Json = serde_json::from_str(r#"{"tag_name":"v1","assets":[]}"#).unwrap();
        assert!(release_archive_asset(&empty).is_none());
    }

    #[test]
    fn release_upload_url_extraction_rejects_non_objects() {
        assert_eq!(
            release_upload_url(
                r#"{"upload_url": "https://uploads.github.com/u{?name,label}"}"#,
                "v1"
            )
            .unwrap(),
            "https://uploads.github.com/u{?name,label}"
        );
        assert!(release_upload_url(r#""just a string""#, "v1").is_err());
    }

    #[test]
    fn copy_refuses_destination_inside_source() {
        let base = std::env::temp_dir().join(format!("typship-d-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        let src = base.join("a");
        fs::create_dir_all(src.join("out")).unwrap();
        fs::write(src.join("f.txt"), "x").unwrap();
        // dst inside src
        assert!(ensure_distinct(&src, &src.join("out").join("b")).is_err());
        // src inside dst
        assert!(ensure_distinct(&src, &base).is_err());
        // same, expressed through dot segments
        assert!(ensure_distinct(&src, &src.join(".").join(".")).is_err());
        // unrelated: fine
        assert!(ensure_distinct(&src, &base.join("b")).is_ok());
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn copy_refuses_alias_destinations_through_dots() {
        // A destination written with .. segments must not slip past the
        // inside-source check.
        let base = std::env::temp_dir().join(format!("typship-d2-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        let src = base.join("a");
        fs::create_dir_all(src.join("out")).unwrap();
        assert!(ensure_distinct(&src, &src.join("out").join("..").join("inside")).is_err());
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn relative_link_target_is_absolute() {
        let base = std::env::temp_dir().join(format!("typship-l-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        let src = base.join("nested").join("a");
        fs::create_dir_all(&src).unwrap();
        fs::write(src.join("f.txt"), "x").unwrap();
        let dst = base.join("nested").join("b");
        link(&src.to_string_lossy(), &dst.to_string_lossy(), None).unwrap();
        // The link must resolve back to the real source.
        let linked = fs::read_dir(&dst).unwrap().count();
        assert_eq!(linked, 1);
        assert!(dst.join("f.txt").is_file());
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn link_accepts_relative_input_paths() {
        // Both ends given as relative paths (resolved against the cwd,
        // which for tests is the crate directory). The created link must
        // still point at the real source.
        let base = PathBuf::from("target").join(format!("typship-lr-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        let src = base.join("a");
        fs::create_dir_all(&src).unwrap();
        fs::write(src.join("f.txt"), "x").unwrap();
        let dst = base.join("b");
        let src_rel = format!("./{}", src.to_string_lossy().replace('\\', "/"));
        let dst_rel = format!("./{}", dst.to_string_lossy().replace('\\', "/"));
        link(&src_rel, &dst_rel, None).unwrap();
        assert!(dst.join("f.txt").is_file());
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn writer_refuses_unsplittable_long_paths() {
        // An unsplittable over-long path would need an extended header:
        // refused with a clear error instead (admin review note: we do
        // not create special-format files).
        let base = std::env::temp_dir().join(format!("typship-sp-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        let src = base.join("a");
        fs::create_dir_all(&src).unwrap();
        let long = format!("{}.typ", "l".repeat(150));
        fs::write(src.join(&long), "long").unwrap();
        let err = pack_tarball(&src).unwrap_err().to_string();
        assert!(err.contains("too long for the ustar layout"), "{err}");
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn writer_emits_only_plain_typeflags() {
        let base = std::env::temp_dir().join(format!("typship-tf-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        let src = base.join("a");
        fs::create_dir_all(src.join("sub")).unwrap();
        fs::write(src.join("plain.txt"), "x").unwrap();
        fs::write(src.join("sub/deep.txt"), "y").unwrap();
        // A long path that splits cleanly into a ustar prefix + name.
        let long_dir = "d".repeat(60);
        let long_name = format!("{}.typ", "n".repeat(90));
        fs::create_dir_all(src.join(&long_dir)).unwrap();
        fs::write(src.join(&long_dir).join(&long_name), "long").unwrap();
        let gz = pack_tarball(&src).unwrap();
        // Inspect the uncompressed tar stream's typeflags.
        let mut raw = Vec::new();
        MultiGzDecoder::new(&gz[..]).read_to_end(&mut raw).unwrap();
        let mut flags = Vec::new();
        let mut pos = 0;
        while pos + 512 <= raw.len() {
            let header = &raw[pos..pos + 512];
            if header.iter().all(|&b| b == 0) {
                break;
            }
            let size = octal(&header[124..136]).unwrap();
            flags.push(header[156]);
            pos += 512 + ((size as usize).div_ceil(512)) * 512;
        }
        assert!(
            flags.iter().all(|f| matches!(f, b'0' | b'5')),
            "only plain entries expected: {flags:?}"
        );
        // The long path round-trips through the ustar prefix split.
        let dst = base.join("out");
        extract_tarball(&gz, &dst, None).unwrap();
        assert_eq!(
            fs::read(dst.join(&long_dir).join(&long_name)).unwrap(),
            b"long"
        );
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn writer_output_roundtrips_through_reader() {
        // The writer's own directory entries (trailing `/`) must be
        // accepted by the reader.
        let base = std::env::temp_dir().join(format!("typship-wr-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        let src = base.join("src");
        fs::create_dir_all(src.join("inner")).unwrap();
        fs::write(src.join("typst.toml"), "m").unwrap();
        fs::write(src.join("inner/lib.typ"), "x").unwrap();
        let gz = pack_tarball(&src).unwrap();
        let dst = base.join("out");
        extract_tarball(&gz, &dst, None).unwrap();
        assert!(dst.join("typst.toml").is_file());
        assert!(dst.join("inner/lib.typ").is_file());
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn roundtrip_preserves_structure() {
        let base = std::env::temp_dir().join(format!("typship-r-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);

        // 1. A pack with a manifest: contents land at the destination top.
        let src = base.join("a");
        fs::create_dir_all(src.join("src")).unwrap();
        fs::write(src.join("typst.toml"), "manifest").unwrap();
        fs::write(src.join("src/main.typ"), "#set page()").unwrap();
        let gz = pack_tarball(&src).unwrap();
        let dst = base.join("b1");
        extract_tarball(&gz, &base.join("t1"), None).unwrap();
        let root = find_pack_root(&base.join("t1")).unwrap();
        copy_tree(&root, &dst).unwrap();
        assert!(dst.join("typst.toml").is_file());
        assert!(dst.join("src/main.typ").is_file());

        // 2. A directory without a manifest keeps its structure exactly.
        let src = base.join("c");
        fs::create_dir_all(src.join("src")).unwrap();
        fs::write(src.join("src/main.typ"), "x").unwrap();
        let gz = pack_tarball(&src).unwrap();
        let dst = base.join("b2");
        extract_tarball(&gz, &base.join("t2"), None).unwrap();
        let root = find_pack_root(&base.join("t2")).unwrap();
        copy_tree(&root, &dst).unwrap();
        assert!(dst.join("src/main.typ").is_file());
        assert!(!dst.join("main.typ").is_file());

        // 3. A wrapper archive: the manifest marks the pack root.
        let wrapped = base.join("w");
        fs::create_dir_all(wrapped.join("repo").join("src")).unwrap();
        fs::write(wrapped.join("repo").join("typst.toml"), "m").unwrap();
        fs::write(wrapped.join("repo").join("src/lib.typ"), "z").unwrap();
        let gz = pack_tarball(&wrapped).unwrap();
        let dst = base.join("b4");
        extract_tarball(&gz, &base.join("t4"), None).unwrap();
        let root = find_pack_root(&base.join("t4")).unwrap();
        copy_tree(&root, &dst).unwrap();
        assert!(dst.join("typst.toml").is_file());
        assert!(dst.join("src/lib.typ").is_file());

        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn utf8_and_long_names_survive_the_roundtrip() {
        let base = std::env::temp_dir().join(format!("typship-u-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        let src = base.join("a");
        fs::create_dir_all(&src).unwrap();
        fs::write(src.join("中文.typ"), "hello").unwrap();
        // A long multi-byte path that splits cleanly into a ustar
        // prefix + name (prefix ≤155 bytes, name ≤100 bytes); each
        // directory component stays at or under 100 bytes, since a
        // single over-long component is refused by the writer contract.
        let long_dir = "目".repeat(33); // 99 bytes, fits the name field directly
        let long_name = format!("{}.typ", "录".repeat(30)); // 93 bytes, fits the name
        // 99 + 1 + 93 = 193 bytes: the file entry needs the prefix split.
        fs::create_dir_all(src.join(&long_dir)).unwrap();
        fs::write(src.join(&long_dir).join(&long_name), "long").unwrap();
        let gz = pack_tarball(&src).unwrap();
        let dst = base.join("b");
        extract_tarball(&gz, &dst, None).unwrap();
        assert_eq!(fs::read(dst.join("中文.typ")).unwrap(), b"hello");
        assert_eq!(
            fs::read(dst.join(&long_dir).join(&long_name)).unwrap(),
            b"long"
        );
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn locate_subdir_has_no_arbitrary_depth_search() {
        // The contract: only the single-subdirectory chain (up to three
        // levels) is traversed; a first segment deeper than that is not
        // found (documents the limitation).
        let base = std::env::temp_dir().join(format!("typship-deep-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        let deep = base.join("a").join("b").join("c").join("d").join("target");
        fs::create_dir_all(&deep).unwrap();
        assert!(locate_subdir(&base, "target").is_none());
        // Within the chain depth it resolves.
        assert!(locate_subdir(&base, "a/b/target_placeholder").is_none()); // absent
        let within = base.join("a").join("b").join("target");
        fs::create_dir_all(&within).unwrap();
        assert!(locate_subdir(&base, "b/target").is_some());
        let _ = fs::remove_dir_all(&base);
    }

    // 资源预算（条数/总量/单成员/下载上限）已按 admin 指示（2026-11-08「不要做没必要的限制」）整体移除，原预算测试随之删除；
    // 剩下防线＝成员类型白名单、路径校验、短读检查与流尾校验。

    #[test]
    fn truncated_body_is_retried_until_success() {
        // Response declares 20 bytes but delivers 2 and closes: the body
        // read fails, which is transient, so a second request follows.
        let truncated: &[u8] =
            b"HTTP/1.1 200 OK\r\nContent-Length: 20\r\nConnection: close\r\n\r\nok";
        let full: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";
        let (url, count) = mock_raw_server(&[truncated, full]);
        let body = fetch_bytes(&format!("{url}/f")).unwrap();
        assert_eq!(body, b"ok".to_vec());
        assert_eq!(count.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn locate_subdir_crosses_wrapper_and_single_chain() {
        // A GitHub wrapper followed by the repository's own single-child
        // directory: the full subpath must resolve.
        let base = std::env::temp_dir().join(format!("typship-ls-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        let sub = base.join("repo-HEAD").join("sub");
        fs::create_dir_all(sub.join("inner")).unwrap();
        fs::write(sub.join("lib.typ"), "x").unwrap();
        assert!(locate_subdir(&base, "sub").is_some());
        assert!(locate_subdir(&base, "sub/inner").is_some());
        // A registry-style nested path below the wrapper.
        let pkg = base
            .join("repo-HEAD")
            .join("packages")
            .join("preview")
            .join("name");
        fs::create_dir_all(&pkg).unwrap();
        assert!(find_in_chain(&base, "packages/preview/name").is_some());
        assert!(find_in_chain(&base, "packages/absent").is_none());
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn link_falls_back_to_copy_when_ends_are_not_linkable() {
        // dir -> tarball: not linkable on the destination side, so the
        // command copies.
        let base = std::env::temp_dir().join(format!("typship-lc-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        let src = base.join("a");
        fs::create_dir_all(&src).unwrap();
        fs::write(src.join("f.txt"), "x").unwrap();
        let tgz = base.join("out.tar.gz");
        link(&src.to_string_lossy(), &tgz.to_string_lossy(), None).unwrap();
        assert!(tgz.is_file());
        // tarball -> dir: not linkable on the source side, so it copies
        // (and the manifest-less tree keeps its structure).
        let dst = base.join("out");
        link(&tgz.to_string_lossy(), &dst.to_string_lossy(), None).unwrap();
        assert!(dst.join("f.txt").is_file());
        let _ = fs::remove_dir_all(&base);
    }

    /// Build a gzipped tar from (path, data) pairs through the writer.
    fn gz_of(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut raw = Vec::new();
        for (path, data) in entries {
            raw.extend_from_slice(&raw_header(path.as_bytes(), b'0', data.len()));
            raw.extend_from_slice(data);
            let pad = (512 - (data.len() % 512)) % 512;
            raw.extend_from_slice(&vec![0u8; pad]);
        }
        raw.extend_from_slice(&[0u8; 1024]);
        gz_of_raw(&raw)
    }

    /// Compress raw (uncompressed) tar bytes.
    fn gz_of_raw(raw: &[u8]) -> Vec<u8> {
        let mut enc = GzEncoder::new(Vec::new(), Compression::default());
        enc.write_all(raw).unwrap();
        enc.finish().unwrap()
    }

    /// A single plain-file tar entry (header + data + padding), raw.
    fn tar_file_entry(name: &str, contents: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&raw_header(name.as_bytes(), b'0', contents.len()));
        out.extend_from_slice(contents);
        out.extend_from_slice(&vec![0u8; (512 - contents.len() % 512) % 512]);
        out
    }

    /// A valid ustar header with a computed checksum.
    fn raw_header(name: &[u8], typeflag: u8, size: usize) -> [u8; 512] {
        let mut header = [0u8; 512];
        header[..name.len().min(100)].copy_from_slice(&name[..name.len().min(100)]);
        let mode = if typeflag == b'5' {
            b"0000755\x00"
        } else {
            b"0000644\x00"
        };
        header[100..108].copy_from_slice(mode);
        header[108..116].copy_from_slice(b"0000000\x00");
        header[116..124].copy_from_slice(b"0000000\x00");
        let size_field = format!("{size:011o}\x00");
        header[124..136].copy_from_slice(size_field.as_bytes());
        header[136..148].copy_from_slice(b"00000000000\x00");
        header[148..156].copy_from_slice(b"        ");
        header[156] = typeflag;
        header[257..263].copy_from_slice(b"ustar\x00");
        header[263..265].copy_from_slice(b"00");
        let checksum = header.iter().map(|&b| b as u64).sum::<u64>();
        let cs = format!("{checksum:06o}\x00 ");
        header[148..156].copy_from_slice(cs.as_bytes());
        header
    }

    /// A tiny HTTP server answering a scripted sequence of
    /// (status, body) responses (the last one repeats) and counting
    /// the requests it served.
    /// A tiny HTTP server answering one scripted raw byte response per
    /// connection (the last one repeats) and counting requests. Used to
    /// simulate broken bodies (short reads) that the (status, body)
    /// helper cannot express.
    fn mock_raw_server(responses: &[&[u8]]) -> (String, Arc<AtomicUsize>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let count = Arc::new(AtomicUsize::new(0));
        let count2 = count.clone();
        let responses: Vec<Vec<u8>> = responses.iter().map(|r| r.to_vec()).collect();
        std::thread::spawn(move || {
            for (i, stream) in listener.incoming().enumerate() {
                let Ok(mut stream) = stream else { break };
                let mut buf = [0u8; 4096];
                let _ = stream.read(&mut buf);
                let idx = i.min(responses.len() - 1);
                count2.fetch_add(1, Ordering::SeqCst);
                let _ = stream.write_all(&responses[idx]);
                // Dropping the stream closes the connection.
            }
        });
        (format!("http://{addr}"), count)
    }

    fn mock_server(responses: &[(u16, &str)]) -> (String, Arc<AtomicUsize>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let count = Arc::new(AtomicUsize::new(0));
        let count2 = count.clone();
        let responses: Vec<(u16, String)> =
            responses.iter().map(|(c, b)| (*c, b.to_string())).collect();
        std::thread::spawn(move || {
            for (i, stream) in listener.incoming().enumerate() {
                let Ok(mut stream) = stream else { break };
                let mut buf = [0u8; 4096];
                let _ = stream.read(&mut buf);
                let idx = i.min(responses.len() - 1);
                let (code, body) = &responses[idx];
                count2.fetch_add(1, Ordering::SeqCst);
                let reason = if *code == 200 { "OK" } else { "E" };
                let resp = format!(
                    "HTTP/1.1 {code} {reason}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(resp.as_bytes());
            }
        });
        (format!("http://{addr}"), count)
    }
}
