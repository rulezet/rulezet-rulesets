rule ldap_md5_hashed_default_creds_adobe
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for adobe."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a1="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a2="{MD5}Ar2S+qOKqmzA6nXlmTeh7w=="
    $a3="{MD5}Ar2S+qOKqmzA6nXlmTeh7w=="
    $a4="{MD5}KU3jVX2dALPS2KHmqrAozw=="
    $a5="{MD5}KU3jVX2dALPS2KHmqrAozw=="
    $a6="{MD5}usdoADYGDQktNxZy8xG1Cg=="
    $a7="{MD5}pWqUv2scMvU9PyUkxC3vCA=="
    $a8="{MD5}oxQF0nK5Tl0S6aUqZl07/g=="
    $a9="{MD5}5m/ehG79dQXcQiUcbdxQDQ=="
    $a10="{MD5}NFvvm/+hHglF3x4Dz6D7Nw=="
    $a11="{MD5}NFvvm/+hHglF3x4Dz6D7Nw=="
    $a12="{MD5}DF2CzMGL246t7PawCss0qg=="
    $a13="{MD5}DF2CzMGL246t7PawCss0qg=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}