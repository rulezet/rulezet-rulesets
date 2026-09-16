rule sha3_256_hashed_default_creds_polycom
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for polycom."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="fe2c6648c75468d6f4cc5fa16ce33e43f7aefe8754f92a09eee2362b71851b85"
    $a1="c62ac717afa32b3362505f0cc2a1391838ecbb84a67b6b62be8bdca46195decc"
    $a2="01d84a0e148f75e15230702ed415ffbbf9f0e05dd65c708683e4e9ed3c6fbe59"
    $a3="c62ac717afa32b3362505f0cc2a1391838ecbb84a67b6b62be8bdca46195decc"
    $a4="fc1cccc1b9f433a6095e1b515300161ced511ee8880692f9fece2f7b9db81de4"
    $a5="bdb3f8add40dad8b96492731a523f85358d8f3c3ec6458ba9c3aeb02fe8d48ab"
    $a6="a65290535b8f2e82433a5b23f67b8087b135b38473a4a541ad5bf36bf0dd1804"
    $a7="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a8="2ed55ef7eead2dd7377ded21e7a3928ac7be2995b3e804ec86e2fd4c84bfc7f6"
    $a9="c62ac717afa32b3362505f0cc2a1391838ecbb84a67b6b62be8bdca46195decc"
    $a10="fe2c6648c75468d6f4cc5fa16ce33e43f7aefe8754f92a09eee2362b71851b85"
    $a11="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}