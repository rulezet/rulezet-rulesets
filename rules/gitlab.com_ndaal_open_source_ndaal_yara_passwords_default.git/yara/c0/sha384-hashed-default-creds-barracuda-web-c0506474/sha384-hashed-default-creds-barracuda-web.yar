rule sha384_hashed_default_creds_barracuda_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for barracuda_web."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a1="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a2="58c1177d3eccda7bc5107f62179d5b133c5b73ec6b8c8cc823ec22fddabae333faeff9a74bc8cc453e9cc0b43ec7efdd"
    $a3="58c1177d3eccda7bc5107f62179d5b133c5b73ec6b8c8cc823ec22fddabae333faeff9a74bc8cc453e9cc0b43ec7efdd"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}