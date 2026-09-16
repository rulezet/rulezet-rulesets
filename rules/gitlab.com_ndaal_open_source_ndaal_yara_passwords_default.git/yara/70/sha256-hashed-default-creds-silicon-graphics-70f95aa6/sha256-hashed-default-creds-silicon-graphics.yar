rule sha256_hashed_default_creds_silicon_graphics
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for silicon_graphics."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0a7373be0796ab9e1f7c2fdec700220092dd851a692c9fe99680c3636be09454"
    $a1="0a7373be0796ab9e1f7c2fdec700220092dd851a692c9fe99680c3636be09454"
    $a2="c0d2856b74d0df05b9d4456b177950351bd88e98b77f12574dfb7a911acee0d0"
    $a3="c0d2856b74d0df05b9d4456b177950351bd88e98b77f12574dfb7a911acee0d0"
    $a4="d7b44809a0359169b755a7030186df928be6b79eff65dc6534e17aacbca31c49"
    $a5="d7b44809a0359169b755a7030186df928be6b79eff65dc6534e17aacbca31c49"
    $a6="038740ef981ab56f4e0529bec9101d1a1d1181886b0c8a917c98029636341360"
    $a7="038740ef981ab56f4e0529bec9101d1a1d1181886b0c8a917c98029636341360"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}