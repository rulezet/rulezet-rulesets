rule blake2b_hashed_default_creds_davox
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for davox."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a1="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a2="2680bd395076ed72f845aef6218b455c1495fb279e44806051f493e84eeebf92e9dc3b30a0b76a5661b3fa410e2745a354e376170d6df0c6fa5e8d80d6c26b60"
    $a3="2680bd395076ed72f845aef6218b455c1495fb279e44806051f493e84eeebf92e9dc3b30a0b76a5661b3fa410e2745a354e376170d6df0c6fa5e8d80d6c26b60"
    $a4="2680bd395076ed72f845aef6218b455c1495fb279e44806051f493e84eeebf92e9dc3b30a0b76a5661b3fa410e2745a354e376170d6df0c6fa5e8d80d6c26b60"
    $a5="da23f3a4e096b0816ec2070050eac6cd9243240dad0b5cde6573e41d6852939ac5468aa9d81b5fbe156feb231a069f5afe8a5146630abc7807b1e0dcdaeb049a"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}