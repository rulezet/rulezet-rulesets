rule ldap_md5_hashed_default_creds_huawei_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for huawei_ssh."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a1="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a2="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a3="{MD5}46/tAEewgFnQ+toQ9ADB5Q=="
    $a4="{MD5}YrlgNYLAKwJdR56RsA7Tlw=="
    $a5="{MD5}YrlgNYLAKwJdR56RsA7Tlw=="
    $a6="{MD5}oBayiiZp+HbMJOmz2sG9cw=="
    $a7="{MD5}LMQ1OOYsyQNF4VWSIFahsw=="
    $a8="{MD5}HSCj8EmtEfeZvVzy9qK1QQ=="
    $a9="{MD5}7hHLsZBS5AsHqsDKBgwj7g=="
    $a10="{MD5}7hHLsZBS5AsHqsDKBgwj7g=="
    $a11="{MD5}7hHLsZBS5AsHqsDKBgwj7g=="
    $a12="{MD5}hLx+qkXqJkXwMKmOeGbzTA=="
    $a13="{MD5}hLx+qkXqJkXwMKmOeGbzTA=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}