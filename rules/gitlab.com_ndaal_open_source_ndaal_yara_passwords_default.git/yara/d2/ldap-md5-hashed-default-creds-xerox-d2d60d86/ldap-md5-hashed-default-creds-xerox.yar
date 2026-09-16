rule ldap_md5_hashed_default_creds_xerox
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for xerox."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}izLjNuljaBOS+w/+8HKCmg=="
    $a1="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a2="{MD5}PSFyQYzjBcfRbUsFWXxqWQ=="
    $a3="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a4="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a5="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a6="{MD5}k0tTWACxy6j5al1y9y8WEQ=="
    $a7="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a8="{MD5}izLjNuljaBOS+w/+8HKCmg=="
    $a9="{MD5}sLrunSedNPod/XGq25CMPw=="
    $a10="{MD5}tZxnvxlqR1gZHkL3ZnDOug=="
    $a11="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a12="{MD5}X1J765ut8eT7hEtAIfbKHg=="
    $a13="{MD5}e3vCUS7h/tzXa9xokm1Pew=="
    $a14="{MD5}jSqVnmsVTskhWIK4LyjPyw=="
    $a15="{MD5}VK9gQiqtssPeHYfs3jBwDg=="
    $a16="{MD5}3Kqf1PI6rwwp9UC+zzW0bw=="
    $a17="{MD5}AwPKDS7QWa2iAuv7KWvQ/Q=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}