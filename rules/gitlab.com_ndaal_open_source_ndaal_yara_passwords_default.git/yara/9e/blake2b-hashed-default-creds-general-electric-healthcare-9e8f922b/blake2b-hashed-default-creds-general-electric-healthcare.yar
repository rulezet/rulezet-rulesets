rule blake2b_hashed_default_creds_general_electric_healthcare
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for general_electric_healthcare."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a1="f6baa4e6ca08a6b47ef9c182f4af1301998798bb6c2ef7f410c828838f06e86315e419ffc39e7a2799fd918b33e155e03362f693796cfdc01dd269afc6a8dc4c"
    $a2="e3c443dba0236abfb1dee273898cad82def58cd02d4d3d68dc13c27fc1255dda9a569d4c573a117d4cc8fa8525408c6590b79f700a4404ad9b5cd3ea99dd17ff"
    $a3="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a4="e3c443dba0236abfb1dee273898cad82def58cd02d4d3d68dc13c27fc1255dda9a569d4c573a117d4cc8fa8525408c6590b79f700a4404ad9b5cd3ea99dd17ff"
    $a5="e3c443dba0236abfb1dee273898cad82def58cd02d4d3d68dc13c27fc1255dda9a569d4c573a117d4cc8fa8525408c6590b79f700a4404ad9b5cd3ea99dd17ff"
    $a6="971a2ed24ef1107144f857efd569898d09473788c0760160ec11f9c473e0f755497318746d1195d7c17571604398072e0c41a65fe5e840180646257274d3ea62"
    $a7="da23f3a4e096b0816ec2070050eac6cd9243240dad0b5cde6573e41d6852939ac5468aa9d81b5fbe156feb231a069f5afe8a5146630abc7807b1e0dcdaeb049a"
    $a8="cf5b11040faea433a418c2d37fcaa683e11df7d03fa4a97efab8d5321ee010ef957557d7248be8ed5fc2f67b160fd862bc365a2fe928f5dff8319e4f00f6d387"
    $a9="f73ae1654fd863c460ce69617d08f76573ed60b6b71c82b4726f641854a9ef6f86163cc3d3d194f4263f579b78b22d4b9664d876be4fade88312f19606b9e3ff"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}