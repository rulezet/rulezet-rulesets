rule nthash_hashed_default_creds_polycom_vvx_500_phone
{
    meta:
        id = "6oXYuClVmWiIKXmzzVr6Eo"
        fingerprint = "ecc6fccd5bbec5f54b394edc23b770994af65d7b7dff3f2cf0d81987c4edaacc"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for polycom_vvx_500_phone."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5a420e7750b39be09fa29d314fa4b51c"
    $a1="a25b2710ba9de114396adc7dfb0a7235"
    $a2="3dbde697d71690a769204beb12283678"
    $a3="0280777f37d4f4e7c478d21cec701463"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}