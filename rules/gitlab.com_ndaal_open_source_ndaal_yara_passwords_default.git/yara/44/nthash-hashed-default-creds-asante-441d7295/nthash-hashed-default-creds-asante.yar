rule nthash_hashed_default_creds_asante
{
    meta:
        id = "22McNDOBzCs5JEWVszWq17"
        fingerprint = "04725245e91ace16b94a61e5cc21edf87fb0ef461b63f86d29f56db4515c6865"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for asante."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4e7a3d0e7af2a44c77d3343a9edef710"
    $a1="209c6174da490caeb422f3fa5a7ae634"
    $a2="4e7a3d0e7af2a44c77d3343a9edef710"
    $a3="8f62e69c0919247c923b60a23c0e46b4"
    $a4="9e59da9d84fdd2de6aa708a606ca8839"
    $a5="f689cb3717c2c7f273c7254765fbc538"
    $a6="9e59da9d84fdd2de6aa708a606ca8839"
    $a7="29ae0f559cdcda1c08e55c20ccf64961"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}