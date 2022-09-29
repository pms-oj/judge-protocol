#[macro_use]
extern crate static_assertions;

pub mod constants;
pub mod handshake;
pub mod judge;
pub mod packet;
pub mod security;

#[cfg(test)]
mod tests {
    #[test]
    // TODO: Remove this test
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
}
