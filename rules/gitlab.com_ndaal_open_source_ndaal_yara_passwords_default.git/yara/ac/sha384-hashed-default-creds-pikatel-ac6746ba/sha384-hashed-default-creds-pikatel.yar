rule sha384_hashed_default_creds_pikatel
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for pikatel."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="78adb963118a6b884c705fe2d78804315dee8bc32e83863d6a7fb482da08722f0c83cda5c273b4113071627e841a1834"
    $a1="78adb963118a6b884c705fe2d78804315dee8bc32e83863d6a7fb482da08722f0c83cda5c273b4113071627e841a1834"
condition:
    ($a0 and $a1)
}