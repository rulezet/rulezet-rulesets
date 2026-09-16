rule sha224_hashed_default_creds_radware
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for radware."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1f2204c440c9157e336938952ff3a2639b1c7e4fb29c168d98ccac9a"
    $a1="1f2204c440c9157e336938952ff3a2639b1c7e4fb29c168d98ccac9a"
    $a2="6deca2175bfed6830906048cf5ab2611b4fa6b4e2394309ae2f6832b"
    $a3="6deca2175bfed6830906048cf5ab2611b4fa6b4e2394309ae2f6832b"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}