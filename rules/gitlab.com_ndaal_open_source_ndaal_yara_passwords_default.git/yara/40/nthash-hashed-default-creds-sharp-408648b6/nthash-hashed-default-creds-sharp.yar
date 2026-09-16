rule nthash_hashed_default_creds_sharp
{
    meta:
        id = "1fveOG0mht6NZ7Siw17Qk0"
        fingerprint = "6180e27d4e518d5a46e7e0e78e9ad56829b5e27a8228c25971980d4249301228"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sharp."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9424a1be777bea85fc219f8cfe3854df"
    $a1="209c6174da490caeb422f3fa5a7ae634"
    $a2="209c6174da490caeb422f3fa5a7ae634"
    $a3="d144986c6122b1b1654ba39932465528"
    $a4="209c6174da490caeb422f3fa5a7ae634"
    $a5="209c6174da490caeb422f3fa5a7ae634"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}