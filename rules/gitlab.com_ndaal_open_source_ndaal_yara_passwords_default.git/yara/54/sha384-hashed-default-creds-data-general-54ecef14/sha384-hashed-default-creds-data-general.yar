rule sha384_hashed_default_creds_data_general
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for data_general."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="22bd82ebe292d19f24ff56b1055ce899a27cd563698c8c8c0cb51e7920965370a5d6204f021546d40359f815a808c010"
    $a1="22bd82ebe292d19f24ff56b1055ce899a27cd563698c8c8c0cb51e7920965370a5d6204f021546d40359f815a808c010"
    $a2="02881c83829f230781da1515a61c5f0ef2783475b2ff7f5cf17f99b4c2df3993bb3182b176b68086da73b6231addc824"
    $a3="02881c83829f230781da1515a61c5f0ef2783475b2ff7f5cf17f99b4c2df3993bb3182b176b68086da73b6231addc824"
    $a4="22bd82ebe292d19f24ff56b1055ce899a27cd563698c8c8c0cb51e7920965370a5d6204f021546d40359f815a808c010"
    $a5="02881c83829f230781da1515a61c5f0ef2783475b2ff7f5cf17f99b4c2df3993bb3182b176b68086da73b6231addc824"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}