//! Defense-in-depth allocator for secret residuals.
//!
//! Every allocation freed through the process allocator is wiped before it is
//! returned to the underlying allocator. This does not replace explicit
//! `SecretString`/`SecretBytes` zeroization: it is a last line of defense for
//! accidental plaintext `String`/`Vec<u8>` temporaries and third-party code.
//!
//! `realloc` is implemented as alloc + copy + wipe + dealloc rather than
//! delegating to the system allocator's realloc, because the old allocation
//! may otherwise be returned without its previous contents being scrubbed.

use std::alloc::{GlobalAlloc, Layout, System};
use std::ptr;
use zeroize::Zeroize;

pub struct ZeroizingAllocator;

#[global_allocator]
static GLOBAL: ZeroizingAllocator = ZeroizingAllocator;

unsafe impl GlobalAlloc for ZeroizingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        System.alloc(layout)
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        System.alloc_zeroed(layout)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if !ptr.is_null() && layout.size() != 0 {
            let bytes = std::slice::from_raw_parts_mut(ptr, layout.size());
            bytes.zeroize();
        }
        System.dealloc(ptr, layout);
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        if new_size == 0 {
            self.dealloc(ptr, layout);
            return ptr::null_mut();
        }

        let new_layout = match Layout::from_size_align(new_size, layout.align()) {
            Ok(layout) => layout,
            Err(_) => return ptr::null_mut(),
        };
        let new_ptr = self.alloc(new_layout);
        if new_ptr.is_null() {
            return ptr::null_mut();
        }

        let copy_len = layout.size().min(new_size);
        if copy_len != 0 {
            ptr::copy_nonoverlapping(ptr, new_ptr, copy_len);
        }
        self.dealloc(ptr, layout);
        new_ptr
    }
}
