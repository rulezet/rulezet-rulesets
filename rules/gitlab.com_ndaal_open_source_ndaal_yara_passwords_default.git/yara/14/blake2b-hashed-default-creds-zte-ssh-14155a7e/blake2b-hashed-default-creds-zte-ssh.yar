rule blake2b_hashed_default_creds_zte_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for zte_ssh."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a1="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a2="c1655ec09cff4f475a7c2036b481ae6148c0f919bb6fb6315050b9465689b794df017aa051ca3a11d01607a002f5a13d5690628203aa7f811d4c12cd96b36395"
    $a3="c1655ec09cff4f475a7c2036b481ae6148c0f919bb6fb6315050b9465689b794df017aa051ca3a11d01607a002f5a13d5690628203aa7f811d4c12cd96b36395"
    $a4="9e2758c60e5e575293047370f8490e7ab0982b021e7be709446fc39ff03ec69d678866c841a01e15c6c84c6ed696356b4c9790e9fe3793493cf56ecefd23cfe8"
    $a5="da23f3a4e096b0816ec2070050eac6cd9243240dad0b5cde6573e41d6852939ac5468aa9d81b5fbe156feb231a069f5afe8a5146630abc7807b1e0dcdaeb049a"
    $a6="383594ced4c721f45475b82346d125496f3bc10705fc8f96dd9d80ac1956c5a0ce1649c5ed5ec3d70aceaff09f9f2c5b407dfd5ff3096a3595ac9bf2828c9a26"
    $a7="da23f3a4e096b0816ec2070050eac6cd9243240dad0b5cde6573e41d6852939ac5468aa9d81b5fbe156feb231a069f5afe8a5146630abc7807b1e0dcdaeb049a"
    $a8="7c4c19165f106d9de2fcb67a6f4d907be2fa7776b1149ff82b69aa74348c0605ea4ef749ce4f5c2ace34cef80a0ce14a480284aa9b6463317b42a11efb64ec38"
    $a9="7c4c19165f106d9de2fcb67a6f4d907be2fa7776b1149ff82b69aa74348c0605ea4ef749ce4f5c2ace34cef80a0ce14a480284aa9b6463317b42a11efb64ec38"
    $a10="edd5a702c6032fec4099f6ad8e30de3e17579f7757cc5818001e1cff4a93a355bf225cf477f396239d3fdabb98cf4862a471fa25d555553092f5257c71d857d7"
    $a11="edd5a702c6032fec4099f6ad8e30de3e17579f7757cc5818001e1cff4a93a355bf225cf477f396239d3fdabb98cf4862a471fa25d555553092f5257c71d857d7"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}