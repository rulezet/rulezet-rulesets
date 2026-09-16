rule sha3_256_hashed_default_creds_osicom
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for osicom."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ca99d4ece01b003edffe4df8f6cf194070787c3082257836c6a3486bf5512c73"
    $a1="ca99d4ece01b003edffe4df8f6cf194070787c3082257836c6a3486bf5512c73"
    $a2="9691993c31365ae98b83d8273129aebd97d23140f0a028b24b057ee402596b8a"
    $a3="789cf532419e99b67093f10b9059465900d073c466c25efd00771189d38f7e66"
    $a4="79b51d793989974dfb7ea33d388d0016dd93a6e80cdaaac8b34ec2f207c1b70f"
    $a5="79b51d793989974dfb7ea33d388d0016dd93a6e80cdaaac8b34ec2f207c1b70f"
    $a6="bbe53f6251b67bef7e6e8c008916c4c80cfdb55175e912c5ac50c73246425fb1"
    $a7="0bb9383cc5cc81ff3b80d1db0520af11fc6c03bedfac605c5c6a718097a9d3a4"
    $a8="144b335042c98cdeffb44e61d31c20f2773d2a97455a6ba4183e426fb858b64a"
    $a9="9691993c31365ae98b83d8273129aebd97d23140f0a028b24b057ee402596b8a"
    $a10="144b335042c98cdeffb44e61d31c20f2773d2a97455a6ba4183e426fb858b64a"
    $a11="2c99ba746fe048c72ac15b2875c70554fc8373980f3ed859bdda41ea8daebeba"
    $a12="144b335042c98cdeffb44e61d31c20f2773d2a97455a6ba4183e426fb858b64a"
    $a13="79b51d793989974dfb7ea33d388d0016dd93a6e80cdaaac8b34ec2f207c1b70f"
    $a14="bbe53f6251b67bef7e6e8c008916c4c80cfdb55175e912c5ac50c73246425fb1"
    $a15="ca99d4ece01b003edffe4df8f6cf194070787c3082257836c6a3486bf5512c73"
    $a16="0bb9383cc5cc81ff3b80d1db0520af11fc6c03bedfac605c5c6a718097a9d3a4"
    $a17="0bb9383cc5cc81ff3b80d1db0520af11fc6c03bedfac605c5c6a718097a9d3a4"
    $a18="2c99ba746fe048c72ac15b2875c70554fc8373980f3ed859bdda41ea8daebeba"
    $a19="2c99ba746fe048c72ac15b2875c70554fc8373980f3ed859bdda41ea8daebeba"
    $a20="512c0356914d6110d78285c82734e26b6831e37f5ad61db272affe01d4d954ae"
    $a21="f85ff244f49dfb741e6b8837298a000a30bda080f52bb86bad7d27a029dbe8a6"
    $a22="2032a7663effc6b47d3d2476625c0f085d89cdb9d1df44904fe558b65a703cb8"
    $a23="91aa470491a98aca115499d2d65096e90c14e286414587df08ff7304851afb95"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23)
}