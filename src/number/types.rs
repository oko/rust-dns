pub use super::IdentifierError;

#[repr(u16)]
#[deriving(PartialEq,Show)]
pub enum Type {
    A = 1,
    NS = 2,
    MD = 3,
    MF = 4,
    CNAME = 5,
    SOA = 6,
    MB = 7,
    MG = 8,
    MR = 9,
    NULL = 10,
    WKS = 11,
    PTR = 12,
    HINFO = 13,
    MINFO = 14,
    MX = 15,
    TXT = 16,
    RP = 17,
    AFSDB = 18,
    X25 = 19,
    ISDN = 20,
    RT = 21,
    NSAP = 22,
    NSAPPTR = 23,
    SIG = 24,
    KEY = 25,
    PX = 26,
    GPOS = 27,
    AAAA = 28,
    LOC = 29,
    NXT = 30,
    EID = 31,
    NIMLOC = 32,
    SRV = 33,
    ATMA = 34,
    NAPTR = 35,
    KX = 36,
    CERT = 37,
    A6 = 38,
    DNAME = 39,
    SINK = 40,
    OPT = 41,
    APL = 42,
    DS = 43,
    SSHFP = 44,
    IPSECKEY = 45,
    RRSIG = 46,
    NSEC = 47,
    DNSKEY = 48,
    DHCID = 49,
    NSEC3 = 50,
    NSEC3PARAM = 51,
    TLSA = 52,
    HIP = 55,
    NINFO = 56,
    RKEY = 57,
    TALINK = 58,
    CDS = 59,
    CDNSKEY = 60,
    OPENPGPKEY = 61,
    SPF = 99,
    UINFO = 100,
    UID = 101,
    GID = 102,
    UNSPEC = 103,
    NID = 104,
    L32 = 105,
    L64 = 106,
    LP = 107,
    EUI48 = 108,
    EUI64 = 109,
    TKEY = 249,
    TSIG = 250,
    IXFR = 251,
    AXFR = 252,
    MAILB = 253,
    MAILA = 254,
    STAR = 255,
    URI = 256,
    CAA = 257,
    TA = 32768,
    DLV = 32769,
    
}

impl Type {
    pub fn from_u16(value: u16) ->  Result<Type, IdentifierError> {
        match value {
            1 => Ok(Type::A),
            2 => Ok(Type::NS),
            3 => Ok(Type::MD),
            4 => Ok(Type::MF),
            5 => Ok(Type::CNAME),
            6 => Ok(Type::SOA),
            7 => Ok(Type::MB),
            8 => Ok(Type::MG),
            9 => Ok(Type::MR),
            10 => Ok(Type::NULL),
            11 => Ok(Type::WKS),
            12 => Ok(Type::PTR),
            13 => Ok(Type::HINFO),
            14 => Ok(Type::MINFO),
            15 => Ok(Type::MX),
            16 => Ok(Type::TXT),
            17 => Ok(Type::RP),
            18 => Ok(Type::AFSDB),
            19 => Ok(Type::X25),
            20 => Ok(Type::ISDN),
            21 => Ok(Type::RT),
            22 => Ok(Type::NSAP),
            23 => Ok(Type::NSAPPTR),
            24 => Ok(Type::SIG),
            25 => Ok(Type::KEY),
            26 => Ok(Type::PX),
            27 => Ok(Type::GPOS),
            28 => Ok(Type::AAAA),
            29 => Ok(Type::LOC),
            30 => Ok(Type::NXT),
            31 => Ok(Type::EID),
            32 => Ok(Type::NIMLOC),
            33 => Ok(Type::SRV),
            34 => Ok(Type::ATMA),
            35 => Ok(Type::NAPTR),
            36 => Ok(Type::KX),
            37 => Ok(Type::CERT),
            38 => Ok(Type::A6),
            39 => Ok(Type::DNAME),
            40 => Ok(Type::SINK),
            41 => Ok(Type::OPT),
            42 => Ok(Type::APL),
            43 => Ok(Type::DS),
            44 => Ok(Type::SSHFP),
            45 => Ok(Type::IPSECKEY),
            46 => Ok(Type::RRSIG),
            47 => Ok(Type::NSEC),
            48 => Ok(Type::DNSKEY),
            49 => Ok(Type::DHCID),
            50 => Ok(Type::NSEC3),
            51 => Ok(Type::NSEC3PARAM),
            52 => Ok(Type::TLSA),
            55 => Ok(Type::HIP),
            56 => Ok(Type::NINFO),
            57 => Ok(Type::RKEY),
            58 => Ok(Type::TALINK),
            59 => Ok(Type::CDS),
            60 => Ok(Type::CDNSKEY),
            61 => Ok(Type::OPENPGPKEY),
            99 => Ok(Type::SPF),
            100 => Ok(Type::UINFO),
            101 => Ok(Type::UID),
            102 => Ok(Type::GID),
            103 => Ok(Type::UNSPEC),
            104 => Ok(Type::NID),
            105 => Ok(Type::L32),
            106 => Ok(Type::L64),
            107 => Ok(Type::LP),
            108 => Ok(Type::EUI48),
            109 => Ok(Type::EUI64),
            249 => Ok(Type::TKEY),
            250 => Ok(Type::TSIG),
            251 => Ok(Type::IXFR),
            252 => Ok(Type::AXFR),
            253 => Ok(Type::MAILB),
            254 => Ok(Type::MAILA),
            255 => Ok(Type::STAR),
            256 => Ok(Type::URI),
            257 => Ok(Type::CAA),
            32768 => Ok(Type::TA),
            32769 => Ok(Type::DLV),
            
            x @ 65280...65534 => Err(IdentifierError::PrivateUseIdentifierError(x as i64)),
            
            65535 => Err(IdentifierError::ReservedIdentifierError(65535 as i64)),
            
            x @ 53...54 => Err(IdentifierError::UnassignedIdentifierError(x as i64)),
            x @ 62...98 => Err(IdentifierError::UnassignedIdentifierError(x as i64)),
            x @ 110...248 => Err(IdentifierError::UnassignedIdentifierError(x as i64)),
            x @ 258...32767 => Err(IdentifierError::UnassignedIdentifierError(x as i64)),
            x @ 32770...65279 => Err(IdentifierError::UnassignedIdentifierError(x as i64)),
            
            x @ _ => Err(IdentifierError::UnknownIdentifierError(x as i64)),
        }
    }
}

#[cfg(test)]
mod test_type {
    use super::Type;
    use super::IdentifierError;
    #[test]
    fn test_variant_identity() {
        assert_eq!(Type::A, Type::from_u16(1).ok().unwrap());
        assert_eq!(Type::NS, Type::from_u16(2).ok().unwrap());
        assert_eq!(Type::MD, Type::from_u16(3).ok().unwrap());
        assert_eq!(Type::MF, Type::from_u16(4).ok().unwrap());
        assert_eq!(Type::CNAME, Type::from_u16(5).ok().unwrap());
        assert_eq!(Type::SOA, Type::from_u16(6).ok().unwrap());
        assert_eq!(Type::MB, Type::from_u16(7).ok().unwrap());
        assert_eq!(Type::MG, Type::from_u16(8).ok().unwrap());
        assert_eq!(Type::MR, Type::from_u16(9).ok().unwrap());
        assert_eq!(Type::NULL, Type::from_u16(10).ok().unwrap());
        assert_eq!(Type::WKS, Type::from_u16(11).ok().unwrap());
        assert_eq!(Type::PTR, Type::from_u16(12).ok().unwrap());
        assert_eq!(Type::HINFO, Type::from_u16(13).ok().unwrap());
        assert_eq!(Type::MINFO, Type::from_u16(14).ok().unwrap());
        assert_eq!(Type::MX, Type::from_u16(15).ok().unwrap());
        assert_eq!(Type::TXT, Type::from_u16(16).ok().unwrap());
        assert_eq!(Type::RP, Type::from_u16(17).ok().unwrap());
        assert_eq!(Type::AFSDB, Type::from_u16(18).ok().unwrap());
        assert_eq!(Type::X25, Type::from_u16(19).ok().unwrap());
        assert_eq!(Type::ISDN, Type::from_u16(20).ok().unwrap());
        assert_eq!(Type::RT, Type::from_u16(21).ok().unwrap());
        assert_eq!(Type::NSAP, Type::from_u16(22).ok().unwrap());
        assert_eq!(Type::NSAPPTR, Type::from_u16(23).ok().unwrap());
        assert_eq!(Type::SIG, Type::from_u16(24).ok().unwrap());
        assert_eq!(Type::KEY, Type::from_u16(25).ok().unwrap());
        assert_eq!(Type::PX, Type::from_u16(26).ok().unwrap());
        assert_eq!(Type::GPOS, Type::from_u16(27).ok().unwrap());
        assert_eq!(Type::AAAA, Type::from_u16(28).ok().unwrap());
        assert_eq!(Type::LOC, Type::from_u16(29).ok().unwrap());
        assert_eq!(Type::NXT, Type::from_u16(30).ok().unwrap());
        assert_eq!(Type::EID, Type::from_u16(31).ok().unwrap());
        assert_eq!(Type::NIMLOC, Type::from_u16(32).ok().unwrap());
        assert_eq!(Type::SRV, Type::from_u16(33).ok().unwrap());
        assert_eq!(Type::ATMA, Type::from_u16(34).ok().unwrap());
        assert_eq!(Type::NAPTR, Type::from_u16(35).ok().unwrap());
        assert_eq!(Type::KX, Type::from_u16(36).ok().unwrap());
        assert_eq!(Type::CERT, Type::from_u16(37).ok().unwrap());
        assert_eq!(Type::A6, Type::from_u16(38).ok().unwrap());
        assert_eq!(Type::DNAME, Type::from_u16(39).ok().unwrap());
        assert_eq!(Type::SINK, Type::from_u16(40).ok().unwrap());
        assert_eq!(Type::OPT, Type::from_u16(41).ok().unwrap());
        assert_eq!(Type::APL, Type::from_u16(42).ok().unwrap());
        assert_eq!(Type::DS, Type::from_u16(43).ok().unwrap());
        assert_eq!(Type::SSHFP, Type::from_u16(44).ok().unwrap());
        assert_eq!(Type::IPSECKEY, Type::from_u16(45).ok().unwrap());
        assert_eq!(Type::RRSIG, Type::from_u16(46).ok().unwrap());
        assert_eq!(Type::NSEC, Type::from_u16(47).ok().unwrap());
        assert_eq!(Type::DNSKEY, Type::from_u16(48).ok().unwrap());
        assert_eq!(Type::DHCID, Type::from_u16(49).ok().unwrap());
        assert_eq!(Type::NSEC3, Type::from_u16(50).ok().unwrap());
        assert_eq!(Type::NSEC3PARAM, Type::from_u16(51).ok().unwrap());
        assert_eq!(Type::TLSA, Type::from_u16(52).ok().unwrap());
        assert_eq!(Type::HIP, Type::from_u16(55).ok().unwrap());
        assert_eq!(Type::NINFO, Type::from_u16(56).ok().unwrap());
        assert_eq!(Type::RKEY, Type::from_u16(57).ok().unwrap());
        assert_eq!(Type::TALINK, Type::from_u16(58).ok().unwrap());
        assert_eq!(Type::CDS, Type::from_u16(59).ok().unwrap());
        assert_eq!(Type::CDNSKEY, Type::from_u16(60).ok().unwrap());
        assert_eq!(Type::OPENPGPKEY, Type::from_u16(61).ok().unwrap());
        assert_eq!(Type::SPF, Type::from_u16(99).ok().unwrap());
        assert_eq!(Type::UINFO, Type::from_u16(100).ok().unwrap());
        assert_eq!(Type::UID, Type::from_u16(101).ok().unwrap());
        assert_eq!(Type::GID, Type::from_u16(102).ok().unwrap());
        assert_eq!(Type::UNSPEC, Type::from_u16(103).ok().unwrap());
        assert_eq!(Type::NID, Type::from_u16(104).ok().unwrap());
        assert_eq!(Type::L32, Type::from_u16(105).ok().unwrap());
        assert_eq!(Type::L64, Type::from_u16(106).ok().unwrap());
        assert_eq!(Type::LP, Type::from_u16(107).ok().unwrap());
        assert_eq!(Type::EUI48, Type::from_u16(108).ok().unwrap());
        assert_eq!(Type::EUI64, Type::from_u16(109).ok().unwrap());
        assert_eq!(Type::TKEY, Type::from_u16(249).ok().unwrap());
        assert_eq!(Type::TSIG, Type::from_u16(250).ok().unwrap());
        assert_eq!(Type::IXFR, Type::from_u16(251).ok().unwrap());
        assert_eq!(Type::AXFR, Type::from_u16(252).ok().unwrap());
        assert_eq!(Type::MAILB, Type::from_u16(253).ok().unwrap());
        assert_eq!(Type::MAILA, Type::from_u16(254).ok().unwrap());
        assert_eq!(Type::STAR, Type::from_u16(255).ok().unwrap());
        assert_eq!(Type::URI, Type::from_u16(256).ok().unwrap());
        assert_eq!(Type::CAA, Type::from_u16(257).ok().unwrap());
        assert_eq!(Type::TA, Type::from_u16(32768).ok().unwrap());
        assert_eq!(Type::DLV, Type::from_u16(32769).ok().unwrap());
        
    }

    #[test]
    fn test_range_privateuse_identity() {
        for i in range(65280, 65534u64+1) {
            assert_eq!(IdentifierError::PrivateUseIdentifierError(i as i64), Type::from_u16(i as u16).err().unwrap());
        }
        
    }
    #[test]
    fn test_range_reserved_identity() {
        assert_eq!(IdentifierError::ReservedIdentifierError(65535), Type::from_u16(65535).err().unwrap());
        
    }
    #[test]
    fn test_range_unassigned_identity() {
        for i in range(53, 54u64+1) {
            assert_eq!(IdentifierError::UnassignedIdentifierError(i as i64), Type::from_u16(i as u16).err().unwrap());
        }
        for i in range(62, 98u64+1) {
            assert_eq!(IdentifierError::UnassignedIdentifierError(i as i64), Type::from_u16(i as u16).err().unwrap());
        }
        for i in range(110, 248u64+1) {
            assert_eq!(IdentifierError::UnassignedIdentifierError(i as i64), Type::from_u16(i as u16).err().unwrap());
        }
        for i in range(258, 32767u64+1) {
            assert_eq!(IdentifierError::UnassignedIdentifierError(i as i64), Type::from_u16(i as u16).err().unwrap());
        }
        for i in range(32770, 65279u64+1) {
            assert_eq!(IdentifierError::UnassignedIdentifierError(i as i64), Type::from_u16(i as u16).err().unwrap());
        }
        
    }
    
}