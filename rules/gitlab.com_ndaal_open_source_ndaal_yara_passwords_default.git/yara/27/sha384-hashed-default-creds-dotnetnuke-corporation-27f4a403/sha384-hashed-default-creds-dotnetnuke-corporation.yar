rule sha384_hashed_default_creds_dotnetnuke_corporation
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for dotnetnuke_corporation."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="350ea305609f5d653d208f9cbb0b057fa85e78e9c944ba92deb41016fb717e2b79ce26ae336424139fe40bcaedea33ee"
    $a1="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a2="8de8398339c56a88dfd7de766d27aff5908aa46946cc736497727b9e0eec9ace205f3884bdf8b101ad8421cdb1d7dae9"
    $a3="32906d5059ffeeb04d1b2827668275a056f3aa9c3fe2d7d208b20a6ce51e765b7ffae3a603169691b3726a9451ae9a32"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}