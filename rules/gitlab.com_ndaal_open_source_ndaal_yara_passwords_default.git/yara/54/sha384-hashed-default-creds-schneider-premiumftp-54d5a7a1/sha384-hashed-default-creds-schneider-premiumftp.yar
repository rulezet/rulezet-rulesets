rule sha384_hashed_default_creds_schneider_premiumftp
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for schneider_premiumftp."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4c31fa9f2233521784230faef6e76e1ad97eebd300ef2675ab55ef8dda8b0564ad3a562939020d4ed678ac5201d75845"
    $a1="0e69d9669ab0fe4989553c463d738a416237eed0e502bbd4411a7d55f1284b21d407e087e837042ac27cae5e3651840f"
condition:
    ($a0 and $a1)
}