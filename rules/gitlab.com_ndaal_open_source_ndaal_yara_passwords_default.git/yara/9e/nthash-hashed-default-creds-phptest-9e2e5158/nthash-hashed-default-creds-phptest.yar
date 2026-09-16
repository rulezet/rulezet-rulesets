rule nthash_hashed_default_creds_phptest
{
    meta:
        id = "2paAJ4fDgZjX4AzLA9QjnY"
        fingerprint = "e7eed04dce93f0e98f0c7c22cdbda3840e3d30acfbda4d8807a1c444e8d23039"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for phptest."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7ce21f17c0aee7fb9ceba532d0546ad6"
    $a1="209c6174da490caeb422f3fa5a7ae634"
    $a2="823893adfad2cda6e1a414f3ebdf58f7"
    $a3="823893adfad2cda6e1a414f3ebdf58f7"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}