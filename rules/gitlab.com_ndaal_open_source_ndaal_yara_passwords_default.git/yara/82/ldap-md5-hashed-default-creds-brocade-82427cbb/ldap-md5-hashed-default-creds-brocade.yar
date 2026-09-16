rule ldap_md5_hashed_default_creds_brocade
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for brocade."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}lEpNxKuJCnuuVafFXUAJYA=="
    $a1="{MD5}lUndYGXQGSEUYMWaht1lNg=="
    $a2="{MD5}Wzru79+vzV3ThaIdSGQteA=="
    $a3="{MD5}Y6nw6nu5gFB5a2SehUgYRQ=="
    $a4="{MD5}X03MO1qnZdYdgyfeuILPmQ=="
    $a5="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a6="{MD5}X03MO1qnZdYdgyfeuILPmQ=="
    $a7="{MD5}7hHLsZBS5AsHqsDKBgwj7g=="
    $a8="{MD5}wz4Bhq6wMczGReMfxSMwZg=="
    $a9="{MD5}Y6nw6nu5gFB5a2SehUgYRQ=="
    $a10="{MD5}1iU5hPZBYkahDjHvr3zg8A=="
    $a11="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a12="{MD5}0tR6xb5LsBJ6wWjYOcbmKg=="
    $a13="{MD5}Y6nw6nu5gFB5a2SehUgYRQ=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}