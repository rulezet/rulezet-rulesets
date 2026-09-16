rule sha384_hashed_default_creds_zte_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for zte_ssh."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a1="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a2="b25ed653dd08fcc715078f0e20046873afa39641eb13a5d2b5386e7567aa0ce84e41a936d80dadf1ce4fec4ab0111658"
    $a3="b25ed653dd08fcc715078f0e20046873afa39641eb13a5d2b5386e7567aa0ce84e41a936d80dadf1ce4fec4ab0111658"
    $a4="f24c53ddd7cde394c18be94fe068a5e173f2eb9b3dd5ac27843f45b3ff99ec046016f62962440c18b459039e21a2cbed"
    $a5="7ed8c2c790aa83d6c3e404b5368f6832c18d46a0e98b9c7a7a5e3ef823e2c9f0e310abbf6f7ea9d9d883ccb64ec2736a"
    $a6="5d41c1d5bfdf6009ca9a08f07596bddc6614f9a1117374063e2f30a3d32b3c3b143713d6babe852884639a5c406d722c"
    $a7="7ed8c2c790aa83d6c3e404b5368f6832c18d46a0e98b9c7a7a5e3ef823e2c9f0e310abbf6f7ea9d9d883ccb64ec2736a"
    $a8="46cb0934bc1afda5a06031f9849b0281bb5cd03767e318e0a877c5a51962dbaa7d7f0dc146ce1bd85176d856907aa2c9"
    $a9="46cb0934bc1afda5a06031f9849b0281bb5cd03767e318e0a877c5a51962dbaa7d7f0dc146ce1bd85176d856907aa2c9"
    $a10="7948831df64f1d058e894fab3f4e2c16fcd1b8881ef36935d7ae8a36c6f190a397e560bdaa52054ef8fa2606360de8e5"
    $a11="7948831df64f1d058e894fab3f4e2c16fcd1b8881ef36935d7ae8a36c6f190a397e560bdaa52054ef8fa2606360de8e5"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}