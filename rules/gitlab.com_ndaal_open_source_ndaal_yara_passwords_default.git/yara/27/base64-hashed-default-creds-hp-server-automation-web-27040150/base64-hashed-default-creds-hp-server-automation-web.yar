rule base64_hashed_default_creds_hp_server_automation_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for hp_server_automation_web."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="QWRtaW5pc3RyYXRvcg=="
    $a1="YWRtaW4="
    $a2="YWRtaW4="
    $a3="b3Bzd2FyZV9hZG1pbg=="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}