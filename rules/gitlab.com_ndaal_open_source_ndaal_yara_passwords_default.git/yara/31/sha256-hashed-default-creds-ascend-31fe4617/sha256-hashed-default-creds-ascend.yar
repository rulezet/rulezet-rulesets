rule sha256_hashed_default_creds_ascend
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ascend."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6a19d16c5d8b543833282a7a750a04981e21ec906a5388c03356630dbad24187"
    $a1="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a2="2ea802eeb4485cf32398e8fa1c85d0be431cfa53e21c8cae1e413c628eef2c0c"
    $a3="4813494d137e1631bba301d5acab6e7bb7aa74ce1185d456565ef51d737677b2"
    $a4="79214a67320d0255297ff8f4107aea70e3d674cfa601a81eaa0fe72c93716993"
    $a5="8171bacf32668a8f44b90087ad107ed63170f57154763ba7e44047bf9e5a7be3"
    $a6="2a54483d03dadc8ab9e4f69e68f4340018c3dcb9e63546d55f5e5d88737b81c5"
    $a7="dbed7fe3ca011c3d1fb0fec3bdced5031d4ef17dfce2fa867717f7beeff23d8e"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}