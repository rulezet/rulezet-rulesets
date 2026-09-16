rule sha3_224_hashed_default_creds_silicon_graphics
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for silicon_graphics."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="62c4b1af4ba2f221d933569821a0997059e19bbde671349c5d51768d"
    $a1="62c4b1af4ba2f221d933569821a0997059e19bbde671349c5d51768d"
    $a2="3cd2ee56b00c1db314a8ee2c447a40661e1f93f9d5ae09678f0cd690"
    $a3="3cd2ee56b00c1db314a8ee2c447a40661e1f93f9d5ae09678f0cd690"
    $a4="7661f49c9614243acbe577af50efc47e3c47b5dddf37637cbbed148d"
    $a5="7661f49c9614243acbe577af50efc47e3c47b5dddf37637cbbed148d"
    $a6="73f59cabe9d81169ca10f33c23312876b4ebc6463bf321e3c266f9c9"
    $a7="73f59cabe9d81169ca10f33c23312876b4ebc6463bf321e3c266f9c9"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}