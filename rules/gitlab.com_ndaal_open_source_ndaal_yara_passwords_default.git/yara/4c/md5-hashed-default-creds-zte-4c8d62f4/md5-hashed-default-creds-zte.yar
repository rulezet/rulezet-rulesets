rule md5_hashed_default_creds_zte
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for zte."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3bc6b5525ecd7b7ae368a48ea59f0d68"
    $a1="21232f297a57a5a743894a0e4a801fc3"
    $a2="54913cb23728dc2fcfa6c86fe567f138"
    $a3="21232f297a57a5a743894a0e4a801fc3"
    $a4="ee11cbb19052e40b07aac0ca060c23ee"
    $a5="ee11cbb19052e40b07aac0ca060c23ee"
    $a6="b512c7363366e5afd113029e7cbf5ec2"
    $a7="ed50e8c7eb72b1e8cd4f89af085a7c2a"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}