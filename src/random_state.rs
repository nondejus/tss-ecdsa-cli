use core::hash::BuildHasher;
use std::cell::Cell;
use std::collections::hash_map::DefaultHasher;
use std::fmt;
///
/// This is a replacement for std::collections::hash_map::RandomState.  RandomState
/// requires random data, and acquires it in a way which causes a SEE machine to
/// block forever.  This version is usable inside a SE machine.
///
/// To create a HashMap using this, use it as the third type in the generic, e.g.:
///
/// let x = HashMap<i32, i32, PsRandomState>
///
#[derive(Clone)]
pub struct PsRandomState {
    k0: u64,
    k1: u64,
}

#[allow(dead_code)]
fn hashmap_random_keys() -> (u64, u64) {
    let v = (0, 0);
    v
}

impl PsRandomState {
    /// Constructs a new `PsRandomState` that is initialized with random keys.
    ///
    /// # Examples
    ///
    /// ```
    /// use psrandomstate::RandomState;
    ///
    /// let s = PsRandomState::new();
    /// ```
    #[inline]
    #[allow(deprecated)]
    pub fn new() -> PsRandomState {
        thread_local!(static KEYS: Cell<(u64, u64)> = {
            Cell::new((0, 0))
        });

        KEYS.with(|keys| {
            let (k0, k1) = keys.get();
            keys.set((k0.wrapping_add(1), k1));
            PsRandomState { k0, k1 }
        })
    }
}

impl BuildHasher for PsRandomState {
    type Hasher = DefaultHasher;
    #[inline]
    #[allow(deprecated)]
    fn build_hasher(&self) -> DefaultHasher {
        DefaultHasher::new()
    }
}

impl Default for PsRandomState {
    /// Constructs a new `RandomState`.
    #[inline]
    fn default() -> PsRandomState {
        PsRandomState::new()
    }
}

impl fmt::Debug for PsRandomState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad("PsRandomState { .. }")
    }
}
