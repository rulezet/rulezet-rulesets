rule blake2b_hashed_default_creds_schneider_m340ftp
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for schneider_m340ftp."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1eb32b2f1ce876fac529b7928657c1b8f885d75663eb082bd07d212ccfd7ea5dc890beacc5d26f47fe2ade13b45cbbc6be0f3b0614e83dd5ec8daf0b8b6bc29a"
    $a1="4548f269ecb8d41644522baed22de8734e3499897742b59ac51cd442e8fbfbc3d19866cdbd7a917e85fa99440e3c5dae7633a78433ecc39b97510fc21ee1c522"
condition:
    ($a0 and $a1)
}