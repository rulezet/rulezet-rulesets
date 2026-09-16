rule sha3_256_hashed_default_creds_wyse
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for wyse."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e787eeef9f29be13838111ba1c1267d6ed9f64d2ee862b863d16c32adff482bf"
    $a1="a00e4d3b352e9d11979549b9eef5dc951592f594488451e6cd86fdc4bce76a53"
    $a2="ff69d6c044543a4c14088b32b7acf489501324dcd38342347f855cff8fd6e9d5"
    $a3="f88ca7c8ebc412c940cc28cdb8ff244ef3b94421ef955241d1f6f54fa6557814"
    $a4="7b01874fbdacafa045b51b9cd998c4840c3c7746b9f5343723dcfde1a0ad979c"
    $a5="f325e8a45689e7c93a6a5540c3ab2ce6feaf763a3166b7dd3fd25cf7c6c6c92c"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}