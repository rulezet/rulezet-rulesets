rule sha384_hashed_default_creds_broadlogic
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for broadlogic."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="cc741da44e4d00e88805b9b575c675e88d69a66380985fdb4421d0382a31ff08c6ba9433d04f7707f029200bbb3096c6"
    $a1="cc741da44e4d00e88805b9b575c675e88d69a66380985fdb4421d0382a31ff08c6ba9433d04f7707f029200bbb3096c6"
    $a2="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a3="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a4="e8d3610af1f69386211907c916abaa27f50ddadbf94af845750fbc230a2d023a89db2fea55fc2115e0e05c60f03f2774"
    $a5="e8d3610af1f69386211907c916abaa27f50ddadbf94af845750fbc230a2d023a89db2fea55fc2115e0e05c60f03f2774"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}