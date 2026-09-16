rule ldap_md5_hashed_default_creds_mx_linux
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mx_linux."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}/gHOKn+6yPr67XyYKgTiKQ=="
    $a1="{MD5}/gHOKn+6yPr67XyYKgTiKQ=="
    $a2="{MD5}Y6nw6nu5gFB5a2SehUgYRQ=="
    $a3="{MD5}Y6nw6nu5gFB5a2SehUgYRQ=="
    $a4="{MD5}jFHoCiHbhyGd0o9PjGtjPA=="
    $a5="{MD5}ox5+nDj617LZR8ozWyMs7Q=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}