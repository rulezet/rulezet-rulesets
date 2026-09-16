rule ldap_md5_hashed_default_creds_carel
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for carel."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}b/8mVWId6Vexi22Cu/UBrA=="
    $a1="{MD5}Y6nw6nu5gFB5a2SehUgYRQ=="
    $a2="{MD5}UICkX2eb3sVLlam+UodM5w=="
    $a3="{MD5}+1l5Qrm8Dk2mOJbQ/ZepPA=="
    $a4="{MD5}OEjyvE/AX+s19SkaM2+kvg=="
    $a5="{MD5}CE4DQ6BIb/BVMN9scFyLtA=="
    $a6="{MD5}Jltq6eErgV3VJJmD+jDQSw=="
    $a7="{MD5}Cs3jiH+JNRo4VCgv6JkTnA=="
    $a8="{MD5}U3TpVsiDvCYEti+Uv7WeZg=="
    $a9="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a10="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a11="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a12="{MD5}h5ylOIVH3z2QckqE71DblA=="
    $a13="{MD5}suCvV7lJT0l9FHIkEXAF+Q=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}