rule blake2b_hashed_default_creds_innovaphone
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for innovaphone."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="bed0149c2f4e1c5047fa6cf58d58943ca64c6816b9d6760671a793fab4c7c1e58771deca2688e00273104170f1db456ca905a7e384c044908b0ad271140d6c4b"
    $a1="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a2="b31187757dd7db9ab4b1003eba9a64a8a6d5ab3a9ec19a45ce4b7c1f92bb20b42dd564871011f4ee834662fcbecfd19b4855765f86f18c6d6822e4ca8e81eaad"
    $a3="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a4="4c2ddaf16e91e595865019cd3bf4953bdec3111eab55ca004476fc5355894c4301e06179990b1a35d421a5088557859c9ed288a8b3ee068df94505160688c60f"
    $a5="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a6="a1425f068d5b6eecd11a713656bed57ca5ff263b2bf5c9c113cc6c63d4c3f18abeb01c44bc65a958e621257d121ec583dd1c2040836674aef5caea7f9c540f91"
    $a7="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a8="91658ff49c3f8cebc6cf335280c767674f58f7236b01700f7efc2b8a6f90fef2ad128f1a0393545878d7e17b7ec225f35e873d0873446e9af0ea74f6493440a2"
    $a9="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}