rule md5_hashed_default_creds_ssh_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ssh_ssh."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7d11dab2055563d3747f24cb36b2994c"
    $a1="7d11dab2055563d3747f24cb36b2994c"
    $a2="4203e8e192124c82386c9542da4b8b4d"
    $a3="63a9f0ea7bb98050796b649e85481845"
    $a4="ed45840f6a6415ca5eb50ae607e9449f"
    $a5="63a9f0ea7bb98050796b649e85481845"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}