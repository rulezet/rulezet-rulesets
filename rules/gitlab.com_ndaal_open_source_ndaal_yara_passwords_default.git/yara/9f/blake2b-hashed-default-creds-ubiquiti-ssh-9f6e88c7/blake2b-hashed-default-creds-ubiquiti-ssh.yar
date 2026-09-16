rule blake2b_hashed_default_creds_ubiquiti_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ubiquiti_ssh."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a1="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a2="c087c9aeff4d51b3a6156d4e53950d1a96d07b8904a75e9d8a23c4d1d3af4e6fb49325ac7cda6dee257b5cfcb79ba6c8de296eb425adaf488f4f0aefd8b9dc72"
    $a3="da23f3a4e096b0816ec2070050eac6cd9243240dad0b5cde6573e41d6852939ac5468aa9d81b5fbe156feb231a069f5afe8a5146630abc7807b1e0dcdaeb049a"
    $a4="c087c9aeff4d51b3a6156d4e53950d1a96d07b8904a75e9d8a23c4d1d3af4e6fb49325ac7cda6dee257b5cfcb79ba6c8de296eb425adaf488f4f0aefd8b9dc72"
    $a5="c087c9aeff4d51b3a6156d4e53950d1a96d07b8904a75e9d8a23c4d1d3af4e6fb49325ac7cda6dee257b5cfcb79ba6c8de296eb425adaf488f4f0aefd8b9dc72"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}