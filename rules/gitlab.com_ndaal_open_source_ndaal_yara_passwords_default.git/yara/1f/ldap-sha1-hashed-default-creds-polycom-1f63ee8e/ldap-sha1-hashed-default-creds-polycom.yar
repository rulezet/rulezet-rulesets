rule ldap_sha1_hashed_default_creds_polycom
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for polycom."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}UerGtHGihNM0HYwMY9DxooYmKhg="
    $a1="{SHA}sMTzZvHR+VDT5KSOZ92E6JOnHlA="
    $a2="{SHA}Jkzb53nCPemPuTJJjSpiIlJKxqg="
    $a3="{SHA}sMTzZvHR+VDT5KSOZ92E6JOnHlA="
    $a4="{SHA}VDa4zWskmN49GYanGwx1kAUliFk="
    $a5="{SHA}s6ypLHk+4OmxqbCl9fwETgUUDfM="
    $a6="{SHA}/sSvTZh0J0+ZRQoRAoYT74s6imk="
    $a7="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a8="{SHA}9+wzccWClysVR3Dc6dheL8YPpKs="
    $a9="{SHA}sMTzZvHR+VDT5KSOZ92E6JOnHlA="
    $a10="{SHA}UerGtHGihNM0HYwMY9DxooYmKhg="
    $a11="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}