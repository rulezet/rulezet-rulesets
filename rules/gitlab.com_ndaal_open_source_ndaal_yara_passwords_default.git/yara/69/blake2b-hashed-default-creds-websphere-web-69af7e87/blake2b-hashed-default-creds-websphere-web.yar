rule blake2b_hashed_default_creds_websphere_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for websphere_web."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f05cc1dce30522404088964d1d989a90a5e73960f95e2bb823058768cab802b81413bfcc8baa755c2319bccccf5255686c9afaf59c769ecd4d2cf66b13d133f1"
    $a1="238c8c11f3d51d2304c78be26341850c0a118fbb4a581016ffc5a161b8cb7992715d0c90a69563cdf78be6bd954fe379c2dfaa3fe44117ce11e5bfc7b801edf4"
condition:
    ($a0 and $a1)
}