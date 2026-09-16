rule blake2s_hashed_default_creds_mitel_networks
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mitel_networks."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="85a117a9aa25d3093b352a4dfb4174b3eb20f1584f354bc8a57e5fd6018dfcf1"
    $a1="9dc72c7553c0507fcbb12e494008fedcc00d1ac06f7c66eaa1eea7dc9c05cd77"
    $a2="59a659c677698d083a9fc19bf369f25b52528b4e60d6201cbc83956332c576c2"
    $a3="293eea3b1d83925a4c5794c9d2a7a049b796ba4831e66bbfff5ea318a264cb3f"
    $a4="59a659c677698d083a9fc19bf369f25b52528b4e60d6201cbc83956332c576c2"
    $a5="e169e8d9a85cd7094d485f8394897dcdd633a9118193f7a6504f2d7119773665"
    $a6="59a659c677698d083a9fc19bf369f25b52528b4e60d6201cbc83956332c576c2"
    $a7="2613de2aa850fddc284e58de1f4cf033b814efe2f240c700102a4b2960cd096d"
    $a8="85a117a9aa25d3093b352a4dfb4174b3eb20f1584f354bc8a57e5fd6018dfcf1"
    $a9="6a01eca427f483c42d4679763c91a80d6609dd6bdc62c10d5ace5243d6532925"
    $a10="59a659c677698d083a9fc19bf369f25b52528b4e60d6201cbc83956332c576c2"
    $a11="541fbae7e33228c5ed638ce6d908ca541b57a43e73c05a9318ebc587849a9449"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}