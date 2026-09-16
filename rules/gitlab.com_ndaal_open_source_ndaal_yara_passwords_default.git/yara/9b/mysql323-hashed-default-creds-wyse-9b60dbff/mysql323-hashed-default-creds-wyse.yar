rule mysql323_hashed_default_creds_wyse
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for wyse."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="14d9d83627fcfc9f"
    $a1="67457e226a1a15bd"
    $a2="74ab8ba42bdff4d8"
    $a3="7e2536a525d52164"
    $a4="38d09abd3efe27ad"
    $a5="52dbd9061c1ca2d7"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}