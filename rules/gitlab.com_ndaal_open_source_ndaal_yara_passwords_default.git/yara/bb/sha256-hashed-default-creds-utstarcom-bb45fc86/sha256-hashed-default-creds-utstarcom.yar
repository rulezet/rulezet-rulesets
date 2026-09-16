rule sha256_hashed_default_creds_utstarcom
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for utstarcom."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="12693b7ddc6b247f54b66dccfbd61e4899d1352da65076a9bd3358919b22923e"
    $a1="12693b7ddc6b247f54b66dccfbd61e4899d1352da65076a9bd3358919b22923e"
    $a2="fc1e777bb6efead7fa6e1f571a36311238044b39ea68850babebca7f694f30c6"
    $a3="298bab1136dcde8c0157190fa5374cbf36c33f79b13a7597da8027c5afe8dc31"
    $a4="c0d2856b74d0df05b9d4456b177950351bd88e98b77f12574dfb7a911acee0d0"
    $a5="c0d2856b74d0df05b9d4456b177950351bd88e98b77f12574dfb7a911acee0d0"
    $a6="9e7f55c19ed75b9bb3bfcc7c65182fdeac0236803c4bf26ed437824b7338956a"
    $a7="9e7f55c19ed75b9bb3bfcc7c65182fdeac0236803c4bf26ed437824b7338956a"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}