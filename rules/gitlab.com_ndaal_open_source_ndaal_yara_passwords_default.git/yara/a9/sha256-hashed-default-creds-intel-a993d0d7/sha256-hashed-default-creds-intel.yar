rule sha256_hashed_default_creds_intel
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for intel."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8fb6d5f37e8055ce720bd0b1d56587f88c0071f285966ba17e72b2b12672aa73"
    $a1="8fb6d5f37e8055ce720bd0b1d56587f88c0071f285966ba17e72b2b12672aa73"
    $a2="2d0ab8eb2fb9d408d646c1375f788b31b8b5030b5d5052f52d42cd8c375e8e68"
    $a3="2d0ab8eb2fb9d408d646c1375f788b31b8b5030b5d5052f52d42cd8c375e8e68"
    $a4="96eebba49dbbf422d245f02290f9d4ed0eb02da9daa6bbceefb162800ff42481"
    $a5="96eebba49dbbf422d245f02290f9d4ed0eb02da9daa6bbceefb162800ff42481"
    $a6="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a7="4813494d137e1631bba301d5acab6e7bb7aa74ce1185d456565ef51d737677b2"
    $a8="1c9aeebe6972c1fed27aae8896682b01cd3a1f035405f59b3702d8c5c90f5857"
    $a9="1ef393f2c0772064cae9403f23e7f8fc6d49bb2939f463f23c4e637231e84da4"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}