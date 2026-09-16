rule sha384_hashed_default_creds_redhat_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for redhat_ssh."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a1="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a2="05274ce7e39f606e4607f9538c8c07eb66a6f4cab902df07e427d04d9f977105dd9ed68b51f35e826107dd5c6f3c7dce"
    $a3="05274ce7e39f606e4607f9538c8c07eb66a6f4cab902df07e427d04d9f977105dd9ed68b51f35e826107dd5c6f3c7dce"
    $a4="081de7624429ffbb0cd03c81da55df6fc8e36d09406bc581aa78c84742fdf45f58d999adb87f89740d2a4f88aaf38209"
    $a5="05274ce7e39f606e4607f9538c8c07eb66a6f4cab902df07e427d04d9f977105dd9ed68b51f35e826107dd5c6f3c7dce"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}