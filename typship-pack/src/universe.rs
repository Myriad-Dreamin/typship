use std::sync::LazyLock;

use ecow::EcoString;

use super::*;

/// A package in the universe registry.
#[derive(Debug, Clone)]
pub struct UniversePackBuilder {
    /// The registry.
    pub registry: EcoString,
}

impl UniversePackBuilder {
    /// Creates a new `UniversePackBuilder` instance.
    pub fn new(registry: EcoString) -> Self {
        Self { registry }
    }

    /// Builds a new `UniversePack` instance.
    pub fn build(self, specifier: PackageSpec) -> UniversePack {
        UniversePack {
            registry: self.registry,
            specifier,
        }
    }
}

/// The default Typst registry.
static DEFAULT_REGISTRY: LazyLock<EcoString> =
    LazyLock::new(|| "https://packages.typst.org".into());

/// A package in the universe registry.
#[derive(Debug, Clone)]
pub struct UniversePack {
    /// The registry.
    pub registry: EcoString,
    /// The package specifier.
    pub specifier: PackageSpec,
}

impl UniversePack {
    /// Creates a new `UniversePack` instance.
    pub fn new(specifier: PackageSpec) -> Self {
        Self {
            registry: DEFAULT_REGISTRY.clone(),
            specifier,
        }
    }
}

impl PackFs for UniversePack {
    fn read_all(
        &mut self,
        f: &mut (dyn FnMut(&str, PackFile) -> PackResult<()> + Send + Sync),
    ) -> PackResult<()> {
        let spec = &self.specifier;
        assert_eq!(spec.namespace, "preview");

        let url = format!(
            "{}/preview/{}-{}.tar.gz",
            self.registry, spec.name, spec.version
        );

        HttpPack::new(self.specifier.clone(), url).read_all(f)
    }
}

impl Pack for UniversePack {}
impl PackExt for UniversePack {}
impl CloneFromPack for UniversePack {}
