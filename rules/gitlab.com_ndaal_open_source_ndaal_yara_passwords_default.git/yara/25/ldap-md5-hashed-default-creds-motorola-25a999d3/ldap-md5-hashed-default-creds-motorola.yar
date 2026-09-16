rule ldap_md5_hashed_default_creds_motorola
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for motorola."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}8zlc1Uz4V9348gVnaP9Jrg=="
    $a1="{MD5}j7BHGaSUqwbTLWbeqzwKVg=="
    $a2="{MD5}dQN5tZJun3KKpsJT0343kg=="
    $a3="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a4="{MD5}X03MO1qnZdYdgyfeuILPmQ=="
    $a5="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a6="{MD5}Pdrrgvu6lk+zRh1OTxNC6w=="
    $a7="{MD5}qqvw05lR8+bD6KeRHfUkwg=="
    $a8="{MD5}mcwvX4TVIAV8UKDrTaFb6w=="
    $a9="{MD5}65GRduusIJndAm7EFSS3Bw=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}