#[macro_use]
extern crate static_assertions;

pub mod constants;
pub mod packet;
pub mod handshake;
pub mod login;

#[cfg(test)]
mod tests {
    #[test]
    // TODO: Remove this test
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
}
