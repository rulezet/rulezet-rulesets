rule sha384_hashed_default_creds_atl
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for atl."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="815576dd012e3086d46b87dbb803d7d0ba5e382a53553db2ccf94f4bc8f55f55f6ad88e7bf1b8b3e61472bc0db02805c"
    $a1="4db800350e79f01139d3565cdfd6534c58a1172a70213cc096b7b7d8e314694559f7dbcb410f65addd9b18b87916e81e"
    $a2="504f008c8fcf8b2ed5dfcde752fc5464ab8ba064215d9c5b5fc486af3d9ab8c81b14785180d2ad7cee1ab792ad44798c"
    $a3="22bd82ebe292d19f24ff56b1055ce899a27cd563698c8c8c0cb51e7920965370a5d6204f021546d40359f815a808c010"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}