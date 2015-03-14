#[inline(always)]
pub fn _read_be_u16(buf: &[u8], idx: &mut usize) -> u16 {
    let out: u16 = ((buf[*idx] as u16) << 8) + (buf[*idx+1] as u16);
    *idx += 2;
    out
}
#[inline(always)]
pub fn _read_be_i32(buf: &[u8], idx: &mut usize) -> i32 {
    let out: i32 = ((buf[*idx] as i32) << 24) + ((buf[*idx+1] as i32) << 16) + ((buf[*idx+2] as i32) << 8) + ((buf[*idx+3] as i32));
    *idx += 4;
    out
}

#[cfg(test)]
mod test_hp_support_functions {
    #[test]
    fn test_read_be_u16() {
        for i in range(0, 65536usize) {
            let b = [((i & 0xFF00) >> 8) as u8, (i & 0x00FF) as u8];
            assert_eq!(super::_read_be_u16(&b, &mut 0), i as u16);
        }
    }
    #[test]
    #[allow(overflowing_literals)]
    fn test_read_be_i32() {
        let test_vals = vec!(-2147483648i32,-20000000, -1, 0, 1, 20000000, 2147483647i32);
        for &i in test_vals.iter() {
            let b = [((i & 0xFF000000) >> 24) as u8, ((i & 0xFF0000) >> 16) as u8, ((i & 0xFF00) >> 8) as u8, (i & 0x00FF) as u8];
            assert_eq!(super::_read_be_i32(&b, &mut 0), i as i32);
        }
    }
}
