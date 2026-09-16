rule sha384_hashed_default_creds_raritan_inc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for raritan_inc."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5cb8c6846552673518ae8b78a4950c43a406b7c2208bd2e7f917f444cb5f931b81e255141ae1ef624a96d0bbcd0dc4c7"
    $a1="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a2="5cb8c6846552673518ae8b78a4950c43a406b7c2208bd2e7f917f444cb5f931b81e255141ae1ef624a96d0bbcd0dc4c7"
    $a3="1f453021f42ec182912866f62259ff70a4d8cebdf97ab03f8002e3871fa14f1675bb979183789815b6794a51b4eb616d"
    $a4="4fe7ac3fdef604776dcbea0e93407236be27a4ad56dc570bc145c640c7bf6900acbee0630f2edf3f15b4133b3bbf304b"
    $a5="84d8cd8acbcd91f836a3d440ab3edab80eb202c58af43514ddcde5a184c31e2c9886902567187645fd950d1a479bf6a5"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}