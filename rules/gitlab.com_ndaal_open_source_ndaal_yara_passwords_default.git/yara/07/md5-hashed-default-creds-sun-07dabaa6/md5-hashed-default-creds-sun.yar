rule md5_hashed_default_creds_sun
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sun."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="21232f297a57a5a743894a0e4a801fc3"
    $a1="21232f297a57a5a743894a0e4a801fc3"
    $a2="4cb9c8a8048fd02294477fcb1a41191a"
    $a3="63a9f0ea7bb98050796b649e85481845"
    $a4="6035d7a170ff97458068c79e64310a38"
    $a5="63a9f0ea7bb98050796b649e85481845"
    $a6="3b1c5bbbbff8515f6e7daeedd5c9b573"
    $a7="63a9f0ea7bb98050796b649e85481845"
    $a8="97c9c694d99f729e1a48940d0b386a9b"
    $a9="97c9c694d99f729e1a48940d0b386a9b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}