rule nthash_hashed_default_creds_electro_industries_gaugetech
{
    meta:
        id = "4tus413uLRDS0jw3waoi91"
        fingerprint = "9198316717187538376f7903a061f58ab1ff61ac57eea322cd12b90b107eecaf"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for electro_industries_gaugetech."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4481b934fc9cad79cb0f5295fa8cfc98"
    $a1="4481b934fc9cad79cb0f5295fa8cfc98"
    $a2="9f24152c45236192c55b70e240f4a8a0"
    $a3="cb29ee667eee1939e2076beb4120a4c4"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}