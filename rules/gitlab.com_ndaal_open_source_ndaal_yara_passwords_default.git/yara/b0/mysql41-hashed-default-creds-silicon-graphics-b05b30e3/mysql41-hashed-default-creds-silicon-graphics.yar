rule mysql41_hashed_default_creds_silicon_graphics
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for silicon_graphics."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*733C60540129614C6C5E22B112BB4EB5E71DED40"
    $a1="*733C60540129614C6C5E22B112BB4EB5E71DED40"
    $a2="*2CEF1DC762FF13BDAB527E25C9B7F51921DB0B18"
    $a3="*2CEF1DC762FF13BDAB527E25C9B7F51921DB0B18"
    $a4="*F46C97C5A17F055A0EB082C6D44EDE61D9599DDA"
    $a5="*F46C97C5A17F055A0EB082C6D44EDE61D9599DDA"
    $a6="*66EC1375EADD4D06F1B64E96E8BAA2E7DAF3F26E"
    $a7="*66EC1375EADD4D06F1B64E96E8BAA2E7DAF3F26E"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}