rule mysql41_hashed_default_creds_electro_industries_gaugetech
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for electro_industries_gaugetech."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*4702A90989423445372DA76271286CF9621AF9D8"
    $a1="*4702A90989423445372DA76271286CF9621AF9D8"
    $a2="*3CA849D8340FD484605AAAF6B492DF6305A71041"
    $a3="*A71984EF6AC9436D515AAEEE36EAD662332C4B45"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}