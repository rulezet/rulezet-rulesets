rule blake2b_hashed_default_creds_meridian
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for meridian."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b75c8c42a1c9216da01ffe3d1f1854706c5dc40a306a6bb76916e8bb93983d469542180373ca305ad5bbf8abc70bce61776f147eb2e041fd8e5367103d674e08"
    $a1="9c0204c6a050d1a92ee3e332261796068dce670fd22f28ddc6e153e708948b30bf9d735ba1efd51e61b6876a2969ae32c3e3cb8fa1076a62c22165022d735d1d"
condition:
    ($a0 and $a1)
}