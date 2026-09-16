rule sha3_384_hashed_default_creds_kodak
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for kodak."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d753a10ef05f90e417efd13a1e773ef9498277672a6ac9b911be3d502fa8fc374675a2b449711bb66547f043d7639a50"
    $a1="0ec4286ba88500d77744e4622cd9bc5d254be13f5be5a9e85d73f07c5e83f0c07e07e4915fff78741f91f41c5308708a"
    $a2="d753a10ef05f90e417efd13a1e773ef9498277672a6ac9b911be3d502fa8fc374675a2b449711bb66547f043d7639a50"
    $a3="d48dc32833c86685c6bd1f4d1332366829151722514d6968d284179ca6b6600295a0ee7659d60e75abd1139fc9fab141"
    $a4="d753a10ef05f90e417efd13a1e773ef9498277672a6ac9b911be3d502fa8fc374675a2b449711bb66547f043d7639a50"
    $a5="c54a3f4d047897ad45fb6933bc57672f8c74ca89f35e0a050d64c1409326737cbaeb3deacc5e0f96181adcf66c1697d2"
    $a6="958b70eb14540c59cf49434cf58702d7e186ffbd7ccb1b41651edd53673dc6f9adf295322ce18177ea2ce75dc9c324a1"
    $a7="885ce4423c696e3936895d764fc64f95908d2d320e36dcf36a6c282d7c878d2c17384e31cdd34b4ba230bcaebc938bcf"
    $a8="46fcc10389c81d0e23a943298f68b0590df5d3a9f7bef73261fbf08f3fe76eda697a7f83c645464491549ca852b193cd"
    $a9="46fcc10389c81d0e23a943298f68b0590df5d3a9f7bef73261fbf08f3fe76eda697a7f83c645464491549ca852b193cd"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}