rule sha3_224_hashed_default_creds_allied_telesis
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for allied_telesis."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="71853ed3baa9c0d0e12e25267edb98e0e043af6ab5e6becfa29fe927"
    $a1="a3920304e1b144139c410c1cbbf79f14fd4ad5fd3d2cbedba983ef81"
condition:
    ($a0 and $a1)
}