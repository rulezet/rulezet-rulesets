rule nthash_hashed_default_creds_textportal
{
    meta:
        id = "3sPYit7rh0vtGgCsko5muN"
        fingerprint = "b1a27c59d1621b635d6501fbe0a5241484811ac0f3fa05a493142a8b20c2e7ef"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for textportal."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7a21990fcd3d759941e45c490f143d5f"
    $a1="0b98cb9de5097d90bc65f32a9dacca06"
    $a2="7a21990fcd3d759941e45c490f143d5f"
    $a3="69d2f83d24e49e2fdbef72d1bf40d1c1"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}