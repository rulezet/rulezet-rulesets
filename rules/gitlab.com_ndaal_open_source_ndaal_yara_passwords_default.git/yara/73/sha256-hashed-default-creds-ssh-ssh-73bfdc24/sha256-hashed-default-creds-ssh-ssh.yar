rule sha256_hashed_default_creds_ssh_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ssh_ssh."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c802e7c149d5f84c96f2a63f357762db6f170a7c049c9ba6b2f740a6780a971e"
    $a1="c802e7c149d5f84c96f2a63f357762db6f170a7c049c9ba6b2f740a6780a971e"
    $a2="8f4ecd2e6bbc91770c629b6ad9b5769b744f140b3519b0d37039c369b23eeb9b"
    $a3="4813494d137e1631bba301d5acab6e7bb7aa74ce1185d456565ef51d737677b2"
    $a4="2ea802eeb4485cf32398e8fa1c85d0be431cfa53e21c8cae1e413c628eef2c0c"
    $a5="4813494d137e1631bba301d5acab6e7bb7aa74ce1185d456565ef51d737677b2"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}