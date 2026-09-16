rule sha384_hashed_default_creds_unknown
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for unknown."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="12444a31ae294042d7a281f5beea379ba4ca3699319673c5f5dc8b64630de9abbc6c338b3f91218b4a09b47f11607b37"
    $a1="12444a31ae294042d7a281f5beea379ba4ca3699319673c5f5dc8b64630de9abbc6c338b3f91218b4a09b47f11607b37"
    $a2="22bd82ebe292d19f24ff56b1055ce899a27cd563698c8c8c0cb51e7920965370a5d6204f021546d40359f815a808c010"
    $a3="22bd82ebe292d19f24ff56b1055ce899a27cd563698c8c8c0cb51e7920965370a5d6204f021546d40359f815a808c010"
    $a4="768412320f7b0aa5812fce428dc4706b3cae50e02a64caa16a782249bfe8efc4b7ef1ccb126255d196047dfedf17a0a9"
    $a5="768412320f7b0aa5812fce428dc4706b3cae50e02a64caa16a782249bfe8efc4b7ef1ccb126255d196047dfedf17a0a9"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}