rule nthash_hashed_default_creds_zte_ssh
{
    meta:
        id = "4lKlpQrfPu2e8BF3lPtZjq"
        fingerprint = "d2a1a6c251fac9240d1c74990977a1c8d4c1df8792216e6f6fac6d35ffb6b01b"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for zte_ssh."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="209c6174da490caeb422f3fa5a7ae634"
    $a1="209c6174da490caeb422f3fa5a7ae634"
    $a2="016f2d39b6b86999e5d5dab89785ba16"
    $a3="016f2d39b6b86999e5d5dab89785ba16"
    $a4="60ee4c7cf22063506be0caf67a98b586"
    $a5="329153f560eb329c0e1deea55e88a1e9"
    $a6="469bd1289684cb7a6868b84042d44251"
    $a7="329153f560eb329c0e1deea55e88a1e9"
    $a8="57d583aa46d571502aad4bb7aea09c70"
    $a9="57d583aa46d571502aad4bb7aea09c70"
    $a10="fd31f5cebebeacfb0635b69f2ac9a63b"
    $a11="fd31f5cebebeacfb0635b69f2ac9a63b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}