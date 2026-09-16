rule blake2b_hashed_default_creds_ibm_storwize_v7000_unified_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ibm_storwize_v7000_unified_ssh."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7ce601dc12ad887bdf9c4c8848edb38cd194f3bfdde20ee85898d0847d38accb2a962a2874b345a7ca3212b9be2156aef1636408af5a64b15a7a9cc7cc41bb00"
    $a1="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a2="b4b2a7043856b7ceed2dca20a921310884c741ab4e478b53d85bec56ef0aa2af64b499a57665e4bc8199700d1665c48827d222f33fb61346c8692f75965c75a1"
    $a3="da23f3a4e096b0816ec2070050eac6cd9243240dad0b5cde6573e41d6852939ac5468aa9d81b5fbe156feb231a069f5afe8a5146630abc7807b1e0dcdaeb049a"
    $a4="493ad8c53ccbc1109d8db20847d7da79cd6055c86c0c0f5a823d3cfb593f8a8e266d2d560fd9713931f0975db479424a3101c308743f792860924a7b5010f749"
    $a5="da283ad64aaa8dade96b1a71e19d9bb0a59d346dae1fafd0a41aa452fa9471372b2fed29d75429f0aab977aaf01215700f166867879afc88565bc0bfc81b8229"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}