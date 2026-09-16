rule md5_hashed_default_creds_raritan_inc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for raritan_inc."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8a913a4043fdbec756efbf51d94e4cc9"
    $a1="21232f297a57a5a743894a0e4a801fc3"
    $a2="8a913a4043fdbec756efbf51d94e4cc9"
    $a3="40448db7510fffb6e2fe7691f5fb91b6"
    $a4="fba0dcef61fbd02682df096fd09ed972"
    $a5="7b98d35c4174f1de389542878d10427d"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}