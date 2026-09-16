rule ldap_md5_hashed_default_creds_schneider
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for schneider."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}T/rz+20AyDIDozHGNVzvBg=="
    $a1="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a2="{MD5}BQavRjTfi+VsrX16JkrgrA=="
    $a3="{MD5}b3t7t2kdwgNZ47lsspLKXA=="
    $a4="{MD5}glN58JvyKhmNdiThG5VKBA=="
    $a5="{MD5}zqvaXX6PyI/K3VWgTY80Ig=="
    $a6="{MD5}i+ICN75uEN0iYTQQapOQ/w=="
    $a7="{MD5}5kz6P9WeMt9XADx0AfSMmQ=="
    $a8="{MD5}kfnWyiwWlb8ioisstqVEiQ=="
    $a9="{MD5}TIzjoeAkg4aUlev5SAL6Qg=="
    $a10="{MD5}LkCth56VUgHfTe2/jUeaEg=="
    $a11="{MD5}LkCth56VUgHfTe2/jUeaEg=="
    $a12="{MD5}41X/OkpZYLhVq9viZm5eHQ=="
    $a13="{MD5}LkCth56VUgHfTe2/jUeaEg=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}