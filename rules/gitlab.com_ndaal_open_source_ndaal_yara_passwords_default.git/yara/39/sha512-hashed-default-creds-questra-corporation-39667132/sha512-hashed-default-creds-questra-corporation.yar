rule sha512_hashed_default_creds_questra_corporation
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for questra_corporation."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b0e0ec7fa0a89577c9341c16cff870789221b310a02cc465f464789407f83f377a87a97d635cac2666147a8fb5fd27d56dea3d4ceba1fc7d02f422dda6794e3c"
    $a1="b0e0ec7fa0a89577c9341c16cff870789221b310a02cc465f464789407f83f377a87a97d635cac2666147a8fb5fd27d56dea3d4ceba1fc7d02f422dda6794e3c"
    $a2="35e503fbe6e2a659cd3cd038297fa2bb8b9f3a69aa95de84823ac99b59cfda4a483c68927ba3d5545073013b957b6fe275d596e2d6eceec659757e6128629ea6"
    $a3="35e503fbe6e2a659cd3cd038297fa2bb8b9f3a69aa95de84823ac99b59cfda4a483c68927ba3d5545073013b957b6fe275d596e2d6eceec659757e6128629ea6"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}