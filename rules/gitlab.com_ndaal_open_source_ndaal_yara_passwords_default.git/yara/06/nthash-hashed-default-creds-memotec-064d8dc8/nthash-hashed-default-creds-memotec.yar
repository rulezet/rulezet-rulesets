rule nthash_hashed_default_creds_memotec
{
    meta:
        id = "3XYN4tSkbwJ4359roBXsOQ"
        fingerprint = "49362e5f23d8d411684c1ab66027d6e902206dd2910f36d0784f13cb3e2577f5"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for memotec."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b547e99ae0f3800915f05cb7a152da11"
    $a1="323bbde019773aef16b88ac95003c0a5"
condition:
    ($a0 and $a1)
}