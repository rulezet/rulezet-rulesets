rule sha3_256_hashed_default_creds_dvb
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for dvb."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1579f6aa3abf1fa981db85b6ca6617c750d895c5f81bc90b50f51e8c1a1b92e0"
    $a1="b7e452aed4a65816040674e4e2578638a62d5b5e8a78784d0907f18cc9ac6c2e"
    $a2="329010af6f34016057f927ca0321de7fa1ab8cbccf745f09918fbe018d024821"
    $a3="a00e4d3b352e9d11979549b9eef5dc951592f594488451e6cd86fdc4bce76a53"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}