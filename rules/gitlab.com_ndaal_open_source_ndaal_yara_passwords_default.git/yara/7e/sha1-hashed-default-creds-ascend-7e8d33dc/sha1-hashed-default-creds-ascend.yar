rule sha1_hashed_default_creds_ascend
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ascend."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="013de34566d41cdc5447f228203bdbaccc61fa07"
    $a1="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a2="b8fad891d4314ddc31d382ce6a48bd3e3ff135b7"
    $a3="dc76e9f0c0006e8f919e0c515c66dbba3982f785"
    $a4="b611ae96194d3c2de7ae260de5149b906c1ba762"
    $a5="9a27718297218c3757c365d357d13f49d0fa3065"
    $a6="a9dd351bee26150accfccd3701c7b0db26379896"
    $a7="accf881e821ed62ca842d34164426a7d9215a948"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}