rule blake2b_hashed_default_creds_us_robotics
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for us_robotics."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8b28f613fa1ccdb1d303704839a0bb196424f425badfa4e4f43808f6812b6bcc0ae43374383bb6e46294d08155a64acbad92084387c73f696f00368ea106ebb4"
    $a1="da23f3a4e096b0816ec2070050eac6cd9243240dad0b5cde6573e41d6852939ac5468aa9d81b5fbe156feb231a069f5afe8a5146630abc7807b1e0dcdaeb049a"
    $a2="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a3="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a4="4ac3be53cae69554238d87f3c554d542c89f70b27ff17cbb11ecf83b5f1d6448738bf96c9682bf20a0b78963a532341834de37669223fbc41e1404bdc14efee2"
    $a5="4ac3be53cae69554238d87f3c554d542c89f70b27ff17cbb11ecf83b5f1d6448738bf96c9682bf20a0b78963a532341834de37669223fbc41e1404bdc14efee2"
    $a6="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a7="da23f3a4e096b0816ec2070050eac6cd9243240dad0b5cde6573e41d6852939ac5468aa9d81b5fbe156feb231a069f5afe8a5146630abc7807b1e0dcdaeb049a"
    $a8="8b28f613fa1ccdb1d303704839a0bb196424f425badfa4e4f43808f6812b6bcc0ae43374383bb6e46294d08155a64acbad92084387c73f696f00368ea106ebb4"
    $a9="bfdac9ce1773da6d763d9a76e0d4e74b0f284e9df7f1a04d9145d04ac1117fee14b6a54e1574c7834604e3b60b122f4674e5f0d1535740a0b612b60abd67e7cf"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}