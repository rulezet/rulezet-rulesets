rule mysql41_hashed_default_creds_norstar
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for norstar."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*04AAFCC7A748D9947332A1BA7FFC6560DA4E11A7"
    $a1="*5777950D2C02A433A59408D4041DE793E4AB55B2"
    $a2="*27828C4808B15E7DD49C7604C296CD917B9CEF1A"
    $a3="*4D76371A278B2B7788290EBF624B01EFB9A30392"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}