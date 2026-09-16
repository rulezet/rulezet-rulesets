rule sha3_384_hashed_default_creds_autodesk
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for autodesk."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e69c161e617d31ed1f3c20de204702fc5a50ea0c407e8694cad97f9031c58b205089d186d1b04522c441b6d22a87dbd6"
    $a1="e69c161e617d31ed1f3c20de204702fc5a50ea0c407e8694cad97f9031c58b205089d186d1b04522c441b6d22a87dbd6"
condition:
    ($a0 and $a1)
}