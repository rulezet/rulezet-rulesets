rule blake2s_hashed_default_creds_allied
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for allied."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="360dfd847ab06765bb81fc7889ad843a09b2ff1e92a4f3fffedbd011cd2531ea"
    $a1="1ba366171bfdf505601934358c61e7d989cd2751271d1fd633ec794d8c3b89ea"
    $a2="fc1cf3a33d9f06da7b413bcc4487c188dc0665202cf566c51c6721a7b2d8b8f5"
    $a3="fc1cf3a33d9f06da7b413bcc4487c188dc0665202cf566c51c6721a7b2d8b8f5"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}