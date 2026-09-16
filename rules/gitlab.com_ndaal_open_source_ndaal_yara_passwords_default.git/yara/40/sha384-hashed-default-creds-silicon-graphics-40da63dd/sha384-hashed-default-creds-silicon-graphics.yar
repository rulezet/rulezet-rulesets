rule sha384_hashed_default_creds_silicon_graphics
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for silicon_graphics."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="05e15148eb181e5ba1bb2fa208756dbfa6a60efd7af22581a4f9e8f39a4d6270636e0b66d2313656f12c7aee33e1e4d8"
    $a1="05e15148eb181e5ba1bb2fa208756dbfa6a60efd7af22581a4f9e8f39a4d6270636e0b66d2313656f12c7aee33e1e4d8"
    $a2="1820ddb65200b50165054c985b456a7038a834016b2a83d695bd6fa67902f24adc343c200e39c05330cb79e9d454aafe"
    $a3="1820ddb65200b50165054c985b456a7038a834016b2a83d695bd6fa67902f24adc343c200e39c05330cb79e9d454aafe"
    $a4="299988a11250fdce76bb4d820c9e749d64b4c44b5543c98cb915a33f37b1a7b0bc4100ef3089a70dd59616731fc0cdbf"
    $a5="299988a11250fdce76bb4d820c9e749d64b4c44b5543c98cb915a33f37b1a7b0bc4100ef3089a70dd59616731fc0cdbf"
    $a6="8cf71de2400e59624ac7e3da1f0e11ef08fe43611a9b795fef417fa9d1eca47cdb776c6a1b6a31aec34dd2799a4dc737"
    $a7="8cf71de2400e59624ac7e3da1f0e11ef08fe43611a9b795fef417fa9d1eca47cdb776c6a1b6a31aec34dd2799a4dc737"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}