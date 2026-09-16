rule mysql41_hashed_default_creds_honeywell
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for honeywell."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*A4B6157319038724E3560894F7F932C8886EBFCF"
    $a1="*9F880DA1329B4B497F247AA25727CCDD5F4DD2E0"
    $a2="*68C04ECC59B0D5CFCD651D36F80EBB2C10474B6F"
    $a3="*90D01ECE1CA9C2266FC268E7728564779F15B041"
    $a4="*FFE3AB81B1C9A5E34E7B33326065ED5C610D6AC1"
    $a5="*34963B1631C5D6E52690C35049C29D34C6E4C961"
    $a6="*11DB58B0DD02E290377535868405F11E4CBEFF58"
    $a7="*B83A2F73F9E74C1EF54E25B4C8A06A68E40CEDF1"
    $a8="*FDCBEFEDD53D954B16F63DCAA3382A7775051D22"
    $a9="*40A898E13D090D32CE8917AEACCE808024FD60C1"
    $a10="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a11="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}