rule md5_hashed_default_creds_allied
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for allied."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3af00c6cad11f7ab5db4467b66ce503e"
    $a1="1d0258c2440a8d19e716292b231e3190"
    $a2="c962b86f3da856a9a67221a7df2038ee"
    $a3="c962b86f3da856a9a67221a7df2038ee"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}