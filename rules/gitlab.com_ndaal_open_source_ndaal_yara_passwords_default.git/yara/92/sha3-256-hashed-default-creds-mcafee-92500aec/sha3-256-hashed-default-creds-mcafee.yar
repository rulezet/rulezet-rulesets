rule sha3_256_hashed_default_creds_mcafee
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mcafee."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="99495699b2f425d716dbfe3c80587129885714d753e6b9fa273fcf80e3eae788"
    $a1="2fcea6680f9614bde24d425dc706e11878c8c595d0a73180c92c84c9fd0da305"
    $a2="b227bff0d28823d4599a39a5b55725b0811c9c13184087e9a122eb572e6ff139"
    $a3="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a4="4acf2d34752638e4da0d6c1845979efd51a8d6af417d7dc268f79b73813eec4b"
    $a5="07de0d9df0f17a31cd9186634664c6d23d62236acd6022e6046bb2fe7568f056"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}