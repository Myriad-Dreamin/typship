use std::str::FromStr;

use typship_pack::{CloneFromPack, GitClPack, MapPack, PackExt, PackageSpec, UniversePackBuilder};

#[test]
fn universe_test() {
    let registry = UniversePackBuilder::new("http://127.0.0.1:11980".into());

    let spec = PackageSpec::from_str("@preview/example:0.1.0").unwrap();

    let mut src = registry.build(spec);

    let mut dst = MapPack::default();
    dst.clone_from_pack(&mut src.filter(|s| s == "typst.toml"))
        .expect("download");

    assert!(dst.files.len() == 1, "downloaded package is bad {dst:?}");
}

#[test]
fn gitcl_test() {
    let mut src = GitClPack::new("local".into(), "https://github.com/hongjr03/typst-zebraw");

    let mut dst = MapPack::default();
    dst.clone_from_pack(&mut src.filter(|s| s == "typst.toml"))
        .expect("clone");

    assert!(dst.files.len() == 1, "downloaded package is bad {dst:?}");
}
