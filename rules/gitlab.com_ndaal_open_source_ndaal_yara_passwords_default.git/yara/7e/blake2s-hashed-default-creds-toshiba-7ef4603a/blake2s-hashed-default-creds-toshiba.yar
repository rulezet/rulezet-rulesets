rule blake2s_hashed_default_creds_toshiba
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for toshiba."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ba2649757ec72ed0b9bd8b3063687767946145f13abcb38e2718fdaad6c771e0"
    $a1="b422627f3ae139067c10b8625441567e61a8be06be00702cdbf249483cec98f0"
    $a2="ba2649757ec72ed0b9bd8b3063687767946145f13abcb38e2718fdaad6c771e0"
    $a3="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a4="122012d2ba8102ee76043865a99ff1ba727661f4074726491a41ac0feb9653bb"
    $a5="0cb8a879dc5d94ed67eb49cc7a4d3052d6a346f2e28fcd9e10e5822aba92eb39"
    $a6="b9847718c3ef331fd9ef26eaaa3cfab9f9bc0909f1516689d08c8ea3fdf30b86"
    $a7="7b866d188933ccc5dfc6f79bd6366c759f7661ff500626bc1b013b6947eb5831"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}