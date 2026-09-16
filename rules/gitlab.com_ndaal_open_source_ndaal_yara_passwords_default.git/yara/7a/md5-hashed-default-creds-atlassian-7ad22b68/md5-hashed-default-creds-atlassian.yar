rule md5_hashed_default_creds_atlassian
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for atlassian."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5f4dcc3b5aa765d61d8327deb882cf99"
    $a1="ecac6fe5e9f6619a392d146e8b0c692a"
    $a2="5f4dcc3b5aa765d61d8327deb882cf99"
    $a3="f0258b6685684c113bad94d91b8fa02a"
    $a4="5f4dcc3b5aa765d61d8327deb882cf99"
    $a5="f6039d44b29456b20f8f373155ae4973"
    $a6="5f4dcc3b5aa765d61d8327deb882cf99"
    $a7="9e9898c7daba7e4e626296dc7c99bd17"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}