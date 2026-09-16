rule blake2b_hashed_default_creds_stuccoboy
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for stuccoboy."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8b6b5cfacea86e407550e3712bdd3377a5105051d3828299534ab19e5434680288753c5a65adea6bc9f5a0e1016f7db73b83cd2e5631f358bd9dcdbed7b1f810"
    $a1="66d50e4f1fede8e36f3e240363bbe4a9fbfe919309dfc486c731c6ab6501f2a93193994357cc6e5212d63099130595bf9d16c4f0e686c357ffe94cd096d0e9ae"
condition:
    ($a0 and $a1)
}