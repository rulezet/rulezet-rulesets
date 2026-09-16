rule sha256_hashed_default_creds_voicegenie_technologies
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for voicegenie_technologies."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="30c952fab122c3f9759f02a6d95c3758b246b4fee239957b2d4fee46e26170c4"
    $a1="30c952fab122c3f9759f02a6d95c3758b246b4fee239957b2d4fee46e26170c4"
condition:
    ($a0 and $a1)
}