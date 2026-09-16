rule blake2b_hashed_default_creds_advantech
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for advantech."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a1="ee276d5d33832a6f05ae3954a7649d1bccc4177cb693d7acdcf423c3e3c5974bb9b5ddbd090ae6929db3cddf9257fff95b212388dd0456dd03a20512aa2d4daa"
    $a2="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a3="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a4="997640bbacba6ece9c0412e7da8646458d1f11202c0a8f162b6a90a962b558ff9ce5ac7721a75b6205338647d6d83ebb9e7514e027917a565445bdedbea9c081"
    $a5="da23f3a4e096b0816ec2070050eac6cd9243240dad0b5cde6573e41d6852939ac5468aa9d81b5fbe156feb231a069f5afe8a5146630abc7807b1e0dcdaeb049a"
    $a6="997640bbacba6ece9c0412e7da8646458d1f11202c0a8f162b6a90a962b558ff9ce5ac7721a75b6205338647d6d83ebb9e7514e027917a565445bdedbea9c081"
    $a7="086d276836c46aa40dcd7d3146548774db2c14fe3d36ac3e6e5a01cc015c6063e23cbce1097cf77a89de52023516baafb55c6f10c425c32fc23b5826fb5207e1"
    $a8="997640bbacba6ece9c0412e7da8646458d1f11202c0a8f162b6a90a962b558ff9ce5ac7721a75b6205338647d6d83ebb9e7514e027917a565445bdedbea9c081"
    $a9="f6baa4e6ca08a6b47ef9c182f4af1301998798bb6c2ef7f410c828838f06e86315e419ffc39e7a2799fd918b33e155e03362f693796cfdc01dd269afc6a8dc4c"
    $a10="997640bbacba6ece9c0412e7da8646458d1f11202c0a8f162b6a90a962b558ff9ce5ac7721a75b6205338647d6d83ebb9e7514e027917a565445bdedbea9c081"
    $a11="ffbd009a16b4af1cdc094f01aa869986899a938bb64792a133952bee291df72556d2e2e0f65961cf92a5dd137929df475303e58cb4525b9fd287387931057159"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}