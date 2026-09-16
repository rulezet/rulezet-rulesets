rule sha3_224_hashed_default_creds_atl
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for atl."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a7265a3fd6c96ae4a1b3c06200005306884bacb1ad1541678c0e9d4f"
    $a1="c45e6d4a6530ff3706cbb89d6decf95215bfd7387ef5d1bc0705b379"
    $a2="b0f3dc043a9c5c05f67651a8c9108b4c2b98e7246b2eea14cb204295"
    $a3="3c77a35671072d55f6995bac6450ea2ad943503143087eabcbc106b5"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}