rule sha1_hashed_default_creds_nice_systems_ltd
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for nice_systems_ltd."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="abf851e862f958be5d7b4a2fb12324249e8e9249"
    $a1="1eda23758be9e36e5e0d2a6a87de584aaca0193f"
    $a2="abf851e862f958be5d7b4a2fb12324249e8e9249"
    $a3="bca1de946a414060b8679e77853d9e32bc721c45"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}