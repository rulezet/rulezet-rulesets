rule sha384_hashed_default_creds_juniper_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for juniper_ssh."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a31d79891919cad24f3264479d76884f581bee32e86778373db3a124de975dd86a40fc7f399b331133b281ab4b11a6ca"
    $a1="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a2="f78bd52b7538fb7ee4c57c995a1bbf476fca33e2adce23d5b114ac159d2616187ac1f2f292e7062d163cdefe5434835f"
    $a3="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a4="6942407cc2d2ceff0e0ab598bc7d6341363dd2182e5ee8d30355402eac065efdcaea8ed734f6cb6e4cbf36d786cd3d06"
    $a5="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a6="f78bd52b7538fb7ee4c57c995a1bbf476fca33e2adce23d5b114ac159d2616187ac1f2f292e7062d163cdefe5434835f"
    $a7="f78bd52b7538fb7ee4c57c995a1bbf476fca33e2adce23d5b114ac159d2616187ac1f2f292e7062d163cdefe5434835f"
    $a8="073ab580db3ec877d60b05b08f33795ffce78c4f265ad8d30a3e84b8881789d5755483b2a26308943b536da2619f6cc8"
    $a9="073ab580db3ec877d60b05b08f33795ffce78c4f265ad8d30a3e84b8881789d5755483b2a26308943b536da2619f6cc8"
    $a10="f29d9083823cd602c0cc12705238aa5e4ab626e558331698f40b170a1a3152837faea8ccb8566b1129e30d057a84ff5d"
    $a11="f29d9083823cd602c0cc12705238aa5e4ab626e558331698f40b170a1a3152837faea8ccb8566b1129e30d057a84ff5d"
    $a12="4e8af95e7fda722d8aa8d194dec4b4a1f0ab4b936afa00cb3a8c3f2b8556a05c920849e731b98e96549707440efbf14c"
    $a13="4092bc3d8a0d7a293f438e15d1a039db25c54342ad87c3d97b4d0554fd6df01bf61704aa1bfe6fdc51c077212a1841e8"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}