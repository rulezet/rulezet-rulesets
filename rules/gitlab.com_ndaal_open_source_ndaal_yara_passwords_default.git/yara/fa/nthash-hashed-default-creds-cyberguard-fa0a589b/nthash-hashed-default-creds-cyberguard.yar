rule nthash_hashed_default_creds_cyberguard
{
    meta:
        id = "7XJvT4N4pRoNSs83B8vSJ4"
        fingerprint = "5140feb9bd4a3d81aee90d9774975640e1683ea24adeef902301e76dfbe52281"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for cyberguard."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="cb832c6b18aa8daed508bd3f2cffc98a"
    $a1="cb832c6b18aa8daed508bd3f2cffc98a"
condition:
    ($a0 and $a1)
}