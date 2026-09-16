rule sha3_384_hashed_default_creds_mentec
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mentec."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b11c68424e670d3d904291ce5b8321b3bc5b9dfd8f3376ac1d006d8b98f37e13099d2968705cc8c8ea37556c208e5ad3"
    $a1="9fd252aa83354cb14c673589fbebdcbb1c37853c189e06563b2f60377473a488a7015f7d60257aefba580ab60a9c53c4"
condition:
    ($a0 and $a1)
}