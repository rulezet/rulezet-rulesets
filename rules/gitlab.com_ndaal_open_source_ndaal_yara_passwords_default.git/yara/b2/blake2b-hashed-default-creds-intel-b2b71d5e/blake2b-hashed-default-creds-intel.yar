rule blake2b_hashed_default_creds_intel
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for intel."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f5b72cdd6f114cdfac80d23f52b9ccbb12c0d065362b039f392391effe37224748a410db32229647bc0bc876292b2bfdecba4a63209398354a665bed6ceb4427"
    $a1="f5b72cdd6f114cdfac80d23f52b9ccbb12c0d065362b039f392391effe37224748a410db32229647bc0bc876292b2bfdecba4a63209398354a665bed6ceb4427"
    $a2="ff54c248b22fe064ec7b2affef94d665a565fb42237cfb86e2faf029ab2bba0bbda8a67c7de04c4ca90bc8016e7afa96e9d8522ad4e572ef308fc98df80689d2"
    $a3="ff54c248b22fe064ec7b2affef94d665a565fb42237cfb86e2faf029ab2bba0bbda8a67c7de04c4ca90bc8016e7afa96e9d8522ad4e572ef308fc98df80689d2"
    $a4="095d371fbfeafb14db15d7875d19eac6a9b33389d79981669b888632d19d3abaa257cc5f00e836e614948735a3b63f2acd91ad6ce441ee8a0a25e0a50f7bd286"
    $a5="095d371fbfeafb14db15d7875d19eac6a9b33389d79981669b888632d19d3abaa257cc5f00e836e614948735a3b63f2acd91ad6ce441ee8a0a25e0a50f7bd286"
    $a6="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a7="da23f3a4e096b0816ec2070050eac6cd9243240dad0b5cde6573e41d6852939ac5468aa9d81b5fbe156feb231a069f5afe8a5146630abc7807b1e0dcdaeb049a"
    $a8="caecd7a0664919ab04a5dba41f0c7e43fc339feb003acd177dcda8bfacbee3fc8a2a570d28a7b072f85fe35b6b5c69380c631befecca190bc52aa9ea83c766b9"
    $a9="42a2aa7db9e0866c30bf5765c025781ff1aa2dd444c0a3c3bf175ee7ec604d0ca47a860ac0310deaeb97da88a6657e09c11002884fc188e1117e599e185643a3"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}