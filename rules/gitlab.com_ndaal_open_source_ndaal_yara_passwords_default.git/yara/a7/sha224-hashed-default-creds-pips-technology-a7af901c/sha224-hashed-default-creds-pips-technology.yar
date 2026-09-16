rule sha224_hashed_default_creds_pips_technology
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for pips_technology."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8445e8f00c0b50e7f5c193fdbbdbd568251e9dfa557b86a0fa9d2e80"
    $a1="8445e8f00c0b50e7f5c193fdbbdbd568251e9dfa557b86a0fa9d2e80"
    $a2="8c4a8629b717f56ab7ef69e4109ffba5544a9b876cadea69b2b9906c"
    $a3="8c4a8629b717f56ab7ef69e4109ffba5544a9b876cadea69b2b9906c"
    $a4="33c6eac441c00060f6f82b7a6b5744728a91961ac546c14fe01f468c"
    $a5="33c6eac441c00060f6f82b7a6b5744728a91961ac546c14fe01f468c"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}