rule sha384_hashed_default_creds_virtual_programming
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for virtual_programming."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a1="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a2="8f7d454f74c32f55bfb9fd1a040d687d19c155a934aa95a130d374775eadea22be5c0aab92f71ed9700d08be49957c13"
    $a3="8f7d454f74c32f55bfb9fd1a040d687d19c155a934aa95a130d374775eadea22be5c0aab92f71ed9700d08be49957c13"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}