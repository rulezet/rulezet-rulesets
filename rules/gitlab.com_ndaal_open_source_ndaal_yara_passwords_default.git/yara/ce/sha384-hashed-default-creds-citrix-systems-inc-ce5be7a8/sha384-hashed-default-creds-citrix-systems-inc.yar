rule sha384_hashed_default_creds_citrix_systems_inc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for citrix_systems_inc."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="902fe947d27da3624192a838bf215458d068f4e5f05544e6a8c7132a50eb3e5cf7d5e180793ff9a5623216033052e4b5"
    $a1="902fe947d27da3624192a838bf215458d068f4e5f05544e6a8c7132a50eb3e5cf7d5e180793ff9a5623216033052e4b5"
    $a2="c8e4be78953b879b1ad771fbc1fb080dfbbdd939ddc1829eb84d1a02bd2f1531b63ab70ec8b37edc6d3107e78157387a"
    $a3="7ed8c2c790aa83d6c3e404b5368f6832c18d46a0e98b9c7a7a5e3ef823e2c9f0e310abbf6f7ea9d9d883ccb64ec2736a"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}