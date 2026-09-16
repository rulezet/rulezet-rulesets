rule blake2b_hashed_default_creds_gitlab
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for gitlab."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1e7f380b70908b7318d4bb7ef77af23eb83e4c3cd555ff5fcd49e9c4a05e774c276a815fe8e3d076a708b40e01ca268432cdb2f9813c1ec40768590a7c60542a"
    $a1="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a2="1e7f380b70908b7318d4bb7ef77af23eb83e4c3cd555ff5fcd49e9c4a05e774c276a815fe8e3d076a708b40e01ca268432cdb2f9813c1ec40768590a7c60542a"
    $a3="0b0fca99fb86bd76323cc883535114175ff2e168d2676daa85475d50b78ec20826ef815b47247f1f023d49377f263e541de87865163ea6961ab6a184fcd485b8"
    $a4="1e7f380b70908b7318d4bb7ef77af23eb83e4c3cd555ff5fcd49e9c4a05e774c276a815fe8e3d076a708b40e01ca268432cdb2f9813c1ec40768590a7c60542a"
    $a5="da23f3a4e096b0816ec2070050eac6cd9243240dad0b5cde6573e41d6852939ac5468aa9d81b5fbe156feb231a069f5afe8a5146630abc7807b1e0dcdaeb049a"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}