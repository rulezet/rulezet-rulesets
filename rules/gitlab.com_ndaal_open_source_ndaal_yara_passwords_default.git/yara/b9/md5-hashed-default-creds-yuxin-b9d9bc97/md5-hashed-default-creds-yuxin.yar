rule md5_hashed_default_creds_yuxin
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for yuxin."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="81dc9bdb52d04dc20036dbd8313ed055"
    $a1="8f9bfe9d1345237cb3b2b205864da075"
    $a2="c5ad7da28110dba8857e73c099b7d793"
    $a3="8f9bfe9d1345237cb3b2b205864da075"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}