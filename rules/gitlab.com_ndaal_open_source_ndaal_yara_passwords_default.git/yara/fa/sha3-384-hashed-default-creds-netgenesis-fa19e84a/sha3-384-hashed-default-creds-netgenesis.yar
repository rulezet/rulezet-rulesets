rule sha3_384_hashed_default_creds_netgenesis
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for netgenesis."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d1d4fce6765938345877c69c3a1035062812d0d0a6be0e9d892c1093b165082a2624306e56eb863b239d842ff84c318f"
    $a1="d1d4fce6765938345877c69c3a1035062812d0d0a6be0e9d892c1093b165082a2624306e56eb863b239d842ff84c318f"
condition:
    ($a0 and $a1)
}