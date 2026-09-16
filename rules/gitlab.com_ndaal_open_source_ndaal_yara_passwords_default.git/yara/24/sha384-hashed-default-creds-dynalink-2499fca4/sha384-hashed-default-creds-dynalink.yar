rule sha384_hashed_default_creds_dynalink
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for dynalink."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a1="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a2="40fe2d4072282a91177bd8d13977c0ed68c7dfccf6e7eca10d481238487e4e318ca87263da20ded9138ca7725aa10263"
    $a3="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a4="a5d2072c62a57f658bec41126c2ec2a130178f2881ba98aa701b7109946dd023576a1180d547e90fa95ba1a2603a9f47"
    $a5="0965c70826460b8578b7601c38a982db287805d9305b073e0f73645a046e55e8fe956fc5c628074d555190dba00a2590"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}