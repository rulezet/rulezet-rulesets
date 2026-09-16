rule sha3_256_hashed_default_creds_openhab
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for openhab."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4ed42af2471b0357080a9b259784da680908149c754ed2227435e1dab5cd3d63"
    $a1="4ed42af2471b0357080a9b259784da680908149c754ed2227435e1dab5cd3d63"
    $a2="8a286b22bbdbd4f0ec1a0f4597612315f8c31cfaf25d9ab1f3d087725f2a7f42"
    $a3="2d1ae558fe7dc2710eb17f5c712e7564db2df29a878b051edb93a5a29d9d04d0"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}