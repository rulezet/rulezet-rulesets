rule mysql323_hashed_default_creds_kodak
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for kodak."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="487825005ab2cd2b"
    $a1="0057a2a446898b90"
    $a2="487825005ab2cd2b"
    $a3="4a8d04ce02c15ef7"
    $a4="487825005ab2cd2b"
    $a5="296a4a8f37d62144"
    $a6="4051fa79125fece7"
    $a7="0778475a4922ba0c"
    $a8="56d7a57b107d747e"
    $a9="56d7a57b107d747e"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}