rule ldap_md5_hashed_default_creds_i2b2_workbench_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for i2b2_workbench_mssql."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}dGopaiVHsaKOzh2bRQIfDQ=="
    $a1="{MD5}glY8MwH7w3l//RcCmE8KLA=="
    $a2="{MD5}KQqiUeESFS4ByxNkZpgPvg=="
    $a3="{MD5}OEwvVhg6pXpEzIW+Ty6bEQ=="
    $a4="{MD5}QoHUP3Ibl2g49sfTSkCU9A=="
    $a5="{MD5}M/iq33AA64pcYxI8i5kzQg=="
    $a6="{MD5}cu7JqqIBTCLfUzftGAAwxw=="
    $a7="{MD5}dcnm76MjNAy8snVqCMQPIw=="
    $a8="{MD5}wWc9EN1pIukvL86UBna4jw=="
    $a9="{MD5}19RySSmrWSLc9WL88nIxEA=="
    $a10="{MD5}a4e7Z4bO5+CuADbwaCcEQg=="
    $a11="{MD5}yZd2yqmtcLvR/Z15BSw1KQ=="
    $a12="{MD5}e1Z50gcLdzsT+OaNIFZwrw=="
    $a13="{MD5}mIn9OcFihf+mamnrnVJPBg=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}