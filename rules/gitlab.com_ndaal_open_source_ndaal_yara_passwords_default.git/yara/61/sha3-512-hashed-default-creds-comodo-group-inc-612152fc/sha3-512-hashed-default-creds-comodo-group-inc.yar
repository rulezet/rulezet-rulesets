rule sha3_512_hashed_default_creds_comodo_group_inc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for comodo_group_inc."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6f3cf829ccef7aa9f146af6a3ef2dd69422c2b012164bed60fb6dbd3b543ca758894d35b086a764fd5bff4d27fb7dc8626805dc033b681a1546acc1669b9be2f"
    $a1="6f3cf829ccef7aa9f146af6a3ef2dd69422c2b012164bed60fb6dbd3b543ca758894d35b086a764fd5bff4d27fb7dc8626805dc033b681a1546acc1669b9be2f"
condition:
    ($a0 and $a1)
}