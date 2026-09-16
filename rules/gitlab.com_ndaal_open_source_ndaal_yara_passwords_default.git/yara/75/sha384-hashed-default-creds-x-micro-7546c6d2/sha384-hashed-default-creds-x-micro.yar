rule sha384_hashed_default_creds_x_micro
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for x_micro."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4092bc3d8a0d7a293f438e15d1a039db25c54342ad87c3d97b4d0554fd6df01bf61704aa1bfe6fdc51c077212a1841e8"
    $a1="4092bc3d8a0d7a293f438e15d1a039db25c54342ad87c3d97b4d0554fd6df01bf61704aa1bfe6fdc51c077212a1841e8"
    $a2="8bd70bf1bd1a4def7b6fdc4ee8132c2a8e2aef2cee6cae5d29b9527061273008a445d8d071a080461281dac33853d212"
    $a3="8bd70bf1bd1a4def7b6fdc4ee8132c2a8e2aef2cee6cae5d29b9527061273008a445d8d071a080461281dac33853d212"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}