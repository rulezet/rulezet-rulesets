rule mysql323_hashed_default_creds_carel
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for carel."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6716cbc473d31e6c"
    $a1="67457e226a1a15bd"
    $a2="58477f9f244b097d"
    $a3="219dff356b14eeb2"
    $a4="2164f5686c7d538a"
    $a5="57510426775c5b0f"
    $a6="5bfcef617378a992"
    $a7="2c77d2ab1a6c61ff"
    $a8="020b226132b5cb46"
    $a9="43e9a4ab75570f5b"
    $a10="43e9a4ab75570f5b"
    $a11="43e9a4ab75570f5b"
    $a12="0472b3b734bdd432"
    $a13="3eb99490241191cf"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}