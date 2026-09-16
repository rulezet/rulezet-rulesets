rule sha224_hashed_default_creds_solarwinds
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for solarwinds."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="868546d685f8ab2d67475bb5a3a195447eddef046e424164c6ffef14"
    $a1="23f30319cbea96b5a45a191135b98b8d72d8648304ea3c35ece06aec"
    $a2="45554197ff700df9a00f1f7e480e4985fc22369881ea3048ffb57220"
    $a3="45554197ff700df9a00f1f7e480e4985fc22369881ea3048ffb57220"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}