rule sha224_hashed_default_creds_offensive_security
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for offensive_security."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3e779dd776252527f0f7178bf00b49151ac85b6559bcdac4eb5eb514"
    $a1="871ce144069ea0816545f52f09cd135d1182262c3b235808fa5a3281"
    $a2="118fbfd07d5d711e25007efd603d686047f69905b5e36db547720c6d"
    $a3="118fbfd07d5d711e25007efd603d686047f69905b5e36db547720c6d"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}