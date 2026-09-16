rule sha224_hashed_default_creds_ektron_inc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ektron_inc."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e8098cf453e9885e01134bf0895ff089cb19962a0430d6db6ac0ca73"
    $a1="e8098cf453e9885e01134bf0895ff089cb19962a0430d6db6ac0ca73"
    $a2="af7f9611506b70ba8393c035b0be590fb4b50d723d80e41e7590e70f"
    $a3="ba6ac6f77ccef0e3e048657cedd65a4089ecb6db72ff6957e1f69091"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}