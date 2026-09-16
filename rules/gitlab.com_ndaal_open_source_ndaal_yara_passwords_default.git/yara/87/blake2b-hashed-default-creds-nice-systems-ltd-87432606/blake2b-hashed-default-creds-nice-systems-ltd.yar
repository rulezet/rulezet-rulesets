rule blake2b_hashed_default_creds_nice_systems_ltd
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for nice_systems_ltd."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="dc19fe1819fbd7d4399914cf4fca237ec614929651ee69b6a2657fd8e1447af12daedacb5135ad4d1b62bfd6d6dbe269055559e1d1b4137859b925c49af957d3"
    $a1="715f92db3d0bb9b61f5d9e600203a54868f6e57d007ef72b02ddfcb1f35959dd8b90100815818584bbae097249f52fb298b5de87f3487ec010d793e1448c8838"
    $a2="dc19fe1819fbd7d4399914cf4fca237ec614929651ee69b6a2657fd8e1447af12daedacb5135ad4d1b62bfd6d6dbe269055559e1d1b4137859b925c49af957d3"
    $a3="6119e635e4a8e28b2b632d1b1dee38c16bce4f695cab9ac769866b1fd9c55b0a723349132dbeffeb7792c62f9e181207c50171c600ceccb39ec7ed7e5cca9d0b"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}