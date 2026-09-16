rule sha384_hashed_default_creds_innovaphone
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for innovaphone."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="72c710ee853be580eace0404d15a8529b999ce768282d247edfb5f1761ad1acf55167f1f02cba51e0bf8851abc52b979"
    $a1="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a2="1f89da18f9aa02ae455c3faa05e234a1b4c9e513a0107a071c949b0f55f20fb58bed242e890318104a82159ceea557dd"
    $a3="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a4="086ee868babc960f520bedea014a51cf9b8207551ac6b07054eaf047b1f5e52fb88a269e992d755e4e427e0aba639a93"
    $a5="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a6="c05383a40b1a728e622cb1a6cca33609b90ba3aa55f7d349905a4bb7df710c4fee71654e4b8f4e3a0b7c1e0edc94ba61"
    $a7="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a8="e5b776b0cc12280635539479c3d9769e2d0e6adf7caf3a31f6a5cdc1523d0fec43589de8caf6b7033307608fc3503754"
    $a9="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}