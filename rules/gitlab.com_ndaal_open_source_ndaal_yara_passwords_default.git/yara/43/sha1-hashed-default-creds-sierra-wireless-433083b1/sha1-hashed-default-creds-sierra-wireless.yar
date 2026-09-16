rule sha1_hashed_default_creds_sierra_wireless
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sierra_wireless."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8cb2237d0679ca88db6464eac60da96345513964"
    $a1="12dea96fec20593566ab75692c9949596833adc9"
    $a2="8cb2237d0679ca88db6464eac60da96345513964"
    $a3="d34652d3325e70b9ec5bd39f9f9d8b7bfc4a6c18"
    $a4="8cb2237d0679ca88db6464eac60da96345513964"
    $a5="40b4f25b1fd956b576d880db2b41182e0444bd1d"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}