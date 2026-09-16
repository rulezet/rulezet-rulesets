rule sha3_256_hashed_default_creds_sitecore_corporation
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sitecore_corporation."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b039179a8a4ce2c252aa6f2f25798251c19b75fc1508d9d511a191e0487d64a7"
    $a1="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a2="80084bf2fba02475726feb2cab2d8215eab14bc6bdd8bfb2c8151257032ecd8b"
    $a3="94c9db1c80801c100cfbef62e40c39a85679743f0190593cc77a8e8d9ed505aa"
    $a4="b039179a8a4ce2c252aa6f2f25798251c19b75fc1508d9d511a191e0487d64a7"
    $a5="55161e9ad867a412f7009dd5f1596548c2e7ebb71e30ed0f2d14684d08742014"
    $a6="4ce8765e720c576f6f5a34ca380b3de5f0912e6e3cc5355542c363891e54594b"
    $a7="55310d2f3370d1c73c9121f190ad644068296f5a8201b95701748f650a18afc3"
    $a8="3e5e3e723953551a2ba2e7c5584bcc4ce407414af1ab2569051e7c9bfa33164d"
    $a9="5e192e1b7f8a525566929005faadc03e6faf376bd68cff7fdc687533928726b1"
    $a10="1b42f48aa4371867a7c51ae6f237f35626e02c12eefa592614e1b10af7769370"
    $a11="e3d2fb373661d01f65d4097daa6043b61b405578dc8711c348dc82b3e0315839"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}