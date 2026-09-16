rule sha3_256_hashed_default_creds_general_electric_healthcare
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for general_electric_healthcare."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a1="bbe53f6251b67bef7e6e8c008916c4c80cfdb55175e912c5ac50c73246425fb1"
    $a2="05d618642a430d4cdebb7fddf959075f8f678f4fa9f7acb02896794d26bffe93"
    $a3="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a4="05d618642a430d4cdebb7fddf959075f8f678f4fa9f7acb02896794d26bffe93"
    $a5="05d618642a430d4cdebb7fddf959075f8f678f4fa9f7acb02896794d26bffe93"
    $a6="cab6da75769c88a833cae2410176b8b9eac006e8a0a75364f8fd8617281249bd"
    $a7="a00e4d3b352e9d11979549b9eef5dc951592f594488451e6cd86fdc4bce76a53"
    $a8="98095726530397f28bab68905464f9a00275f176d660c3d4b1b5665ac5ab98e8"
    $a9="563744be95bddb62d3575b293d29d7317b6694d17b93a0e418c62e66199bb011"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}