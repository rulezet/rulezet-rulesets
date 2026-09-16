rule ldap_md5_hashed_default_creds_wyse
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for wyse."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}4nwkeZPtqWajBHK5Vq7/vw=="
    $a1="{MD5}Y6nw6nu5gFB5a2SehUgYRQ=="
    $a2="{MD5}eNHkcN0qQ9n/TuzZO/m6jQ=="
    $a3="{MD5}xqM5EcxT35vbhKrI2GoFZQ=="
    $a4="{MD5}KCBaGi2Tkn+1g306SIKe9w=="
    $a5="{MD5}m5OhlqyB1VgseCL7+FsbJQ=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}