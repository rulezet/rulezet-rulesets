rule sha1_hashed_default_creds_carestream_health
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for carestream_health."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8eccb6cecfa119da06383342bac920ceb32f7032"
    $a1="f8517a59925f5202736d845f5e7fd9120f345faf"
    $a2="8eccb6cecfa119da06383342bac920ceb32f7032"
    $a3="1621c81b1c54f6b8e2fadf0bca3573747261baff"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}