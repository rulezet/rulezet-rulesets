rule ldap_md5_hashed_default_creds_dotnetnuke_corporation
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for dotnetnuke_corporation."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}Wdz1N9O88ajVNx2Xasscrw=="
    $a1="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a2="{MD5}kYubGKBTQnn1UT3JDohLAw=="
    $a3="{MD5}Z7PbqLxneBAYkut3JJ2zLg=="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}