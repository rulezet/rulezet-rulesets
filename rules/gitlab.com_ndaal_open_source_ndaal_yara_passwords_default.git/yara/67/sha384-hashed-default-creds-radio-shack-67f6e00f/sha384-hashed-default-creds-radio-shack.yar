rule sha384_hashed_default_creds_radio_shack
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for radio_shack."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="2d6b69ebd8df1518c295aadb6c5eaff0b120b4d9d1eeb435cb9b4df80a3d2b4b22a4b820780f51271136e5b6790e7f52"
    $a1="99d9d91ba267eda91e4cd400fe2b30a405da8e7d9f9a260fe2e128ae2536bed5258b933a35d0c29dd2278fe56da112d4"
condition:
    ($a0 and $a1)
}