rule ldap_sha1_hashed_default_creds_mitel_networks
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mitel_networks."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}nwsT/WBHTBtR1YMVXobR7QYN0G8="
    $a1="{SHA}7mZ+GHu+y4W0mF2+85Ak2zoQ160="
    $a2="{SHA}6IjcrDKsBH3TYip1bEweLJspOFg="
    $a3="{SHA}L8QtN/7iyB12fgn7KYtwx0iUD4Y="
    $a4="{SHA}6IjcrDKsBH3TYip1bEweLJspOFg="
    $a5="{SHA}NDuwVyc6CGdOGfgvvo67brhxHwA="
    $a6="{SHA}6IjcrDKsBH3TYip1bEweLJspOFg="
    $a7="{SHA}njchZDeX5NE3PP7A0N9P11d7GVs="
    $a8="{SHA}nwsT/WBHTBtR1YMVXobR7QYN0G8="
    $a9="{SHA}nnMN0CJS+VFX+cpVmlqRODLT9Zg="
    $a10="{SHA}6IjcrDKsBH3TYip1bEweLJspOFg="
    $a11="{SHA}MX8edh8vqo2ngaR2K53MLFytIJo="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}