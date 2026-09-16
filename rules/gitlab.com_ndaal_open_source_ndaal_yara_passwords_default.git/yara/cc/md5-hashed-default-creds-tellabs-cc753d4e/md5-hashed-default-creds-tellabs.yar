rule md5_hashed_default_creds_tellabs
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tellabs."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a7d0e7a977456f60aa36706acc7f5fb5"
    $a1="63a9f0ea7bb98050796b649e85481845"
    $a2="8954462dc06d12348e2ad32f4ea8d25f"
    $a3="2f1e9ae7e6a2f97a21c19fe4c3007a54"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}