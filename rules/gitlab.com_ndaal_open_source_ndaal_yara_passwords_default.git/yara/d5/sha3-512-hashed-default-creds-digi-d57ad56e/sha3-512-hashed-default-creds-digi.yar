rule sha3_512_hashed_default_creds_digi
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for digi."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6e7ebc41bff9d74bbb86b5d60ea292024f8573381159599a29d117d21084f918d5db3a85cd81207af5c365bbaa37bb3a527bd590775cef4ce762135735e5ac4c"
    $a1="8cd824c700eb0c125fff40c8c185d14c5dfe7f32814afac079ba7c20d93bc3c082193243c420fed22ef2474fbb85880e7bc1ca772150a1f759f8ddebca77711f"
    $a2="e9a75486736a550af4fea861e2378305c4a555a05094dee1dca2f68afea49cc3a50e8de6ea131ea521311f4d6fb054a146e8282f8e35ff2e6368c1a62e909716"
    $a3="94e89bd380edb3493e982813bf943696c49b68021410d7ac0ac0b5ebc8fb3e033a063e94760afe76ed933c17e2e00287a781c7887115ef927634bfd412299b2c"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}