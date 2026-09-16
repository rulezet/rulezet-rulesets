rule mysql41_hashed_default_creds_mcafee
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mcafee."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*091BFF6AC1543E97337E8D430D701DCBD4D59314"
    $a1="*2FEE30B4D747DA56BED33AC202816213E8D5D8E4"
    $a2="*01A6717B58FF5C7EAFFF6CB7C96F7428EA65FE4C"
    $a3="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a4="*E80DF769BADBDBF907CA2A9E2A0B0A2AB8A1AC9A"
    $a5="*4CAC2E4641CD81D7526FB0A3E4408A74A087A2EE"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}