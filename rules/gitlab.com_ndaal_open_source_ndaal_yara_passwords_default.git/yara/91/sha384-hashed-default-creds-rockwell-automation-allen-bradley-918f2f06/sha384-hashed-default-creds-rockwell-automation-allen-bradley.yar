rule sha384_hashed_default_creds_rockwell_automation___allen_bradley
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for rockwell_automation___allen_bradley."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a1="cb5d13481d7585712e60785bb95b43ce5a00a4c6380ce30785be8b69c0ab257195d89b9606b266ba5774c5e5ef045a10"
    $a2="a8b64babd0aca91a59bdbb7761b421d4f2bb38280d3a75ba0f21f2bebc45583d446c598660c94ce680c47d19c30783a7"
    $a3="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a4="59f42752047c2f96534afc66eaeabfcab757a5d037d9ece8b140c1dece1b1e8905ad886f3e5f6a601242f69956057b27"
    $a5="bc103de599c019dc3731bf079680d3b4a47f2d5230cf5152a1804658f00a6f9f0942bae24bc4da93b3140bf351b247c0"
    $a6="59f42752047c2f96534afc66eaeabfcab757a5d037d9ece8b140c1dece1b1e8905ad886f3e5f6a601242f69956057b27"
    $a7="59574b4173ec4533369d13cb3b1c4496cc8fdb5a10d22298e26e1952547e91bb624102df5ccbea276a169e2d8c2e3b0f"
    $a8="41b46393b517f1be9e3798fb4961404d9e7acde208b25f44c154360bba29c1f30196f1058fd06d0bc1e12f6f2d6c35fe"
    $a9="41b46393b517f1be9e3798fb4961404d9e7acde208b25f44c154360bba29c1f30196f1058fd06d0bc1e12f6f2d6c35fe"
    $a10="92c6a814f27de333d7883d1a4fda98a1a9042d498c57c4597791f6ddf6d7448cb4371061da793a52c71f2bd88eb98524"
    $a11="4cfb880e9b3d538c7671cb5de2f6523956d42f011838486320897688aee9c49724207bd39e04d9b74d67ea8dd30ec3c1"
    $a12="762325d2e67ae3257b112a4130c54b5ba33d409a884c48ab6b0895cebbf39812a367466e2a8a7bf431cdc58dede41acb"
    $a13="4cfb880e9b3d538c7671cb5de2f6523956d42f011838486320897688aee9c49724207bd39e04d9b74d67ea8dd30ec3c1"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}