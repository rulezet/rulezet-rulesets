rule sha384_hashed_default_creds_ibm_storwize_v7000_unified_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ibm_storwize_v7000_unified_ssh."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8ee416263fbee3734bd97d4d06a3e81b6d9ad840690734b0820ed65821810debcb831bb813f2bb45c6b62cd0c657076a"
    $a1="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a2="053409a4197558e5f75ac94858361c8d82acf09d7a4189508ca8bd9bba57f824ca1d91187902b893e2c4b07dd85b969b"
    $a3="7ed8c2c790aa83d6c3e404b5368f6832c18d46a0e98b9c7a7a5e3ef823e2c9f0e310abbf6f7ea9d9d883ccb64ec2736a"
    $a4="68daa2085274c092300bc1893351b9bace14870a6982124409e5b27ec14942508d606e69654ce2ce6ff4729823e26254"
    $a5="856a24efd702a2ca0d1685bf0f704c0d2370def2cd51fead525025a1019635740d140d2d9ab78a6a8d774ab140d74b70"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}