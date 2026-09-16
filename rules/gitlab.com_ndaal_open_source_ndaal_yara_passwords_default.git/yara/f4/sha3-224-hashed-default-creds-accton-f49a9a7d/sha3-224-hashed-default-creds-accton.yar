rule sha3_224_hashed_default_creds_accton
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for accton."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a3920304e1b144139c410c1cbbf79f14fd4ad5fd3d2cbedba983ef81"
    $a1="a3920304e1b144139c410c1cbbf79f14fd4ad5fd3d2cbedba983ef81"
    $a2="459dd589b578ec3cdf231f0b6213f1c048e6a3ddd0c1c0ce63ca1478"
    $a3="459dd589b578ec3cdf231f0b6213f1c048e6a3ddd0c1c0ce63ca1478"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}