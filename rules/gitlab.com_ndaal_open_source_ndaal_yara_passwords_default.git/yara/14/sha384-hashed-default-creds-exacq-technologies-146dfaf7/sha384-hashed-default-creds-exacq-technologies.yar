rule sha384_hashed_default_creds_exacq_technologies
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for exacq_technologies."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4fa2cd7b1fce5911e023d80dd75d8b7706cddca9b5b324e8812dc792f3c7a38d998f351b9d03e01d9589ae168a69312e"
    $a1="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a2="0db5e13afd47c48cd45a120926dbb4d3eb889c2e5e3086378f2b29b82c36771bf7455000edb9e9e5deb560e39d1f8bcd"
    $a3="46cb0934bc1afda5a06031f9849b0281bb5cd03767e318e0a877c5a51962dbaa7d7f0dc146ce1bd85176d856907aa2c9"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}