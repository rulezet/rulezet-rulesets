rule sha3_512_hashed_default_creds_osmc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for osmc."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="fb4847400871f2f03125d1819e0f68fe6ce045a3475ffb6a789351cae00fdda2b9f6bba94cc1737ce419fc83c1fb91798de7a91bb7da64da70652d4354d034a3"
    $a1="fb4847400871f2f03125d1819e0f68fe6ce045a3475ffb6a789351cae00fdda2b9f6bba94cc1737ce419fc83c1fb91798de7a91bb7da64da70652d4354d034a3"
condition:
    ($a0 and $a1)
}