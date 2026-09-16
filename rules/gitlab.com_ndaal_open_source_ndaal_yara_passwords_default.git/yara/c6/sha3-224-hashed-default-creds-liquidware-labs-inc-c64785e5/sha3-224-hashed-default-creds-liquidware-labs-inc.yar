rule sha3_224_hashed_default_creds_liquidware_labs_inc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for liquidware_labs_inc."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="46ec5989d941258fbcba2f7abd73c4e12c63ca2557f05d5774979dbb"
    $a1="4dec25da1dc96489a4acaa05caa4eaeeffe14568d864d7813b399e75"
condition:
    ($a0 and $a1)
}