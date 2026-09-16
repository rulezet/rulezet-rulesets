rule sha384_hashed_default_creds_ubiquiti_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ubiquiti_ssh."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a1="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a2="dfa6565e08c58600772ea633020fbff6f438eb361b8326473e01f56e37b35e58d5457dc2af808efc30b633ee154453fd"
    $a3="7ed8c2c790aa83d6c3e404b5368f6832c18d46a0e98b9c7a7a5e3ef823e2c9f0e310abbf6f7ea9d9d883ccb64ec2736a"
    $a4="dfa6565e08c58600772ea633020fbff6f438eb361b8326473e01f56e37b35e58d5457dc2af808efc30b633ee154453fd"
    $a5="dfa6565e08c58600772ea633020fbff6f438eb361b8326473e01f56e37b35e58d5457dc2af808efc30b633ee154453fd"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}