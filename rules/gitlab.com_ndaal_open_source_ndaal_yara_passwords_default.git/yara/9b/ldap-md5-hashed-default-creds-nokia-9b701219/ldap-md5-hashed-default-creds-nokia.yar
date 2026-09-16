rule ldap_md5_hashed_default_creds_nokia
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for nokia."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}3SaL2CbZlHyh/rXphRqWPQ=="
    $a1="{MD5}3SaL2CbZlHyh/rXphRqWPQ=="
    $a2="{MD5}Kec5a2t+i4qyDaq83hx3Mg=="
    $a3="{MD5}Kec5a2t+i4qyDaq83hx3Mg=="
    $a4="{MD5}YmCOCK3Cmo1tvJdU5lnxJQ=="
    $a5="{MD5}YmCOCK3Cmo1tvJdU5lnxJQ=="
    $a6="{MD5}gnzLDuqKcGxMNKFokfhOew=="
    $a7="{MD5}pXHZachmH7A0Kv0I5XHfoA=="
    $a8="{MD5}Jo4nBWo+Us83VdGTy+sFlA=="
    $a9="{MD5}pXHZachmH7A0Kv0I5XHfoA=="
    $a10="{MD5}DCOovymhkfGK7oFHN+Km7A=="
    $a11="{MD5}Y6nw6nu5gFB5a2SehUgYRQ=="
    $a12="{MD5}lsqdL5S4ceaTO1GADiTpFw=="
    $a13="{MD5}Y6nw6nu5gFB5a2SehUgYRQ=="
    $a14="{MD5}gnzLDuqKcGxMNKFokfhOew=="
    $a15="{MD5}ExY3kJbIXkiuPIQm4VNu1A=="
    $a16="{MD5}6puzqpUHI/rOc0I4AmJQdA=="
    $a17="{MD5}6puzqpUHI/rOc0I4AmJQdA=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}