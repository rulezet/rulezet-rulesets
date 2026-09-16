rule mysql41_hashed_default_creds_saf_tehnika
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for saf_tehnika."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*79FDB91603D47B98A8531FC34D742AF3EAA13A5E"
    $a1="*9F880DA1329B4B497F247AA25727CCDD5F4DD2E0"
    $a2="*5D23BD05B9A1F623575235217C9CD11BD2C15C4D"
    $a3="*9224A48D92F7A120189F9A36C4C8874AE44259E0"
    $a4="*1975D095AC033CAF4E1BF94F7202A9BBFEEB66F1"
    $a5="*1975D095AC033CAF4E1BF94F7202A9BBFEEB66F1"
    $a6="*E47B6004CB1F38FC7FCDB83336E6200D9DD98663"
    $a7="*60CE05C60319F4878B7A51EDF3DC98089E0C6E26"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}