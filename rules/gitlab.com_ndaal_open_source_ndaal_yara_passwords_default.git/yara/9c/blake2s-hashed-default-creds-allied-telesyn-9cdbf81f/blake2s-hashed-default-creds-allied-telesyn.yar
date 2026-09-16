rule blake2s_hashed_default_creds_allied_telesyn
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for allied_telesyn."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1ba366171bfdf505601934358c61e7d989cd2751271d1fd633ec794d8c3b89ea"
    $a1="1ba366171bfdf505601934358c61e7d989cd2751271d1fd633ec794d8c3b89ea"
    $a2="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a3="1ba366171bfdf505601934358c61e7d989cd2751271d1fd633ec794d8c3b89ea"
    $a4="360dfd847ab06765bb81fc7889ad843a09b2ff1e92a4f3fffedbd011cd2531ea"
    $a5="c433cfbbb003de680514002697229db8740b3820a4ff914f6e1ea24f953a5730"
    $a6="360dfd847ab06765bb81fc7889ad843a09b2ff1e92a4f3fffedbd011cd2531ea"
    $a7="1ba366171bfdf505601934358c61e7d989cd2751271d1fd633ec794d8c3b89ea"
    $a8="fc1cf3a33d9f06da7b413bcc4487c188dc0665202cf566c51c6721a7b2d8b8f5"
    $a9="fc1cf3a33d9f06da7b413bcc4487c188dc0665202cf566c51c6721a7b2d8b8f5"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}