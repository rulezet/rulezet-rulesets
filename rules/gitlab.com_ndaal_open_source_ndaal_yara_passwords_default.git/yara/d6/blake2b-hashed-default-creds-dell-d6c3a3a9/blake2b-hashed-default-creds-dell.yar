rule blake2b_hashed_default_creds_dell
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for dell."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9f171b86b7587c25d2f8f3a5dbd7f8f49061735a938caf8bc632509940653ba4d38ebbd7761f02ef25fd2cbe32c1cc0fefc9a10fcc2150b5f05c96c704c5e8e5"
    $a1="da23f3a4e096b0816ec2070050eac6cd9243240dad0b5cde6573e41d6852939ac5468aa9d81b5fbe156feb231a069f5afe8a5146630abc7807b1e0dcdaeb049a"
    $a2="7c863950ac93c93692995e4732ce1e1466ad74a775352ffbaaf2a4a4ce9b549d0b414a1f3150452be6c7c72c694a7cb46f76452917298d33e67611f0a42addb8"
    $a3="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a4="0fbae8c2bf79bd7751855d526513c9a2bc84d773de9bc9f7a4bb15f6dad3c52647061fb8e9c7a66a830a04d830ba6aab06d6b6f2bf7a90e510eee02acb94bf7b"
    $a5="da23f3a4e096b0816ec2070050eac6cd9243240dad0b5cde6573e41d6852939ac5468aa9d81b5fbe156feb231a069f5afe8a5146630abc7807b1e0dcdaeb049a"
    $a6="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a7="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a8="ee9571c711b94967896fcb640fa19376c669d859f4cffd1b2bc5660da8e020b5a6e01031e4044986bda07dea29593aae5013ccdbe47a922149a23dde9fff4fbe"
    $a9="715f92db3d0bb9b61f5d9e600203a54868f6e57d007ef72b02ddfcb1f35959dd8b90100815818584bbae097249f52fb298b5de87f3487ec010d793e1448c8838"
    $a10="fa3a147cd2a2861057edc69183e7171e0dfbbd76ecda9875c201c546c378e9ecf75d0cb13b22536540061ce0093cc5dbb08720e3f64ecc5991bdd2a624afa072"
    $a11="fe03ff34c8b135660afc2d240ba444ee1305182be6e0da51ff1343408b646da7401ea8c6ea4b87ffd04ae03c687eed6f6d078b35c9272c77a50c383ac8a8931f"
    $a12="a00776d99560ad680b1d3a12a848b54d0238559ae1264af9a8aceba445af6a3593c457f684ab23f9ef18a09bfd6f33b894f51775e169a6832e816b121e5cb34f"
    $a13="da23f3a4e096b0816ec2070050eac6cd9243240dad0b5cde6573e41d6852939ac5468aa9d81b5fbe156feb231a069f5afe8a5146630abc7807b1e0dcdaeb049a"
    $a14="11ece2058bc1d9b592b585b11d018f73067086e1e8b4d53c4cb6871bb9ba5c5673bca32a323b8d09819a1b9c35014610a0c71ac25f2e4f72c5e0db9fe2973fae"
    $a15="d5c6d67da69608b42fdac3fb407f209c71efa344d77e446f12e8b73bae873e8837e8eb03b30b29f4ac27a99ec080be30cf8e5da6423942a22f51dea3f0f196b4"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}