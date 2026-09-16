rule ldap_md5_hashed_default_creds_rsa
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for rsa."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}yTzNeLIHZSg0YhazsvcB5g=="
    $a1="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a2="{MD5}fifyOOeU0UXxRQdJ1H7h6w=="
    $a3="{MD5}IAzrJoB9a/mf1vTw0cpU1A=="
    $a4="{MD5}zdHIJJHRIoY3wijx15Ez9w=="
    $a5="{MD5}6woZF5diTdOkj6aB0wYSEg=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}