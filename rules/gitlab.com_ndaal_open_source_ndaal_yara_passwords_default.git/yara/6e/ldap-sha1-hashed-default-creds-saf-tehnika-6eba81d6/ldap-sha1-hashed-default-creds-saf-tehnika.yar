rule ldap_sha1_hashed_default_creds_saf_tehnika
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for saf_tehnika."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}ggV6OXGO9YAvniA2ANaZA6WW5qc="
    $a1="{SHA}s6ypLHk+4OmxqbCl9fwETgUUDfM="
    $a2="{SHA}4MWU5mqUhTQj5cg+cKDQ+wnZy1E="
    $a3="{SHA}4GhRSrbsfyeQftoDgklDEJto2Ys="
    $a4="{SHA}l5aAn32uSC0xI8FlhfK2D5dAd5Y="
    $a5="{SHA}l5aAn32uSC0xI8FlhfK2D5dAd5Y="
    $a6="{SHA}E+r2wRN33kDWDivbhR88O2DBxXE="
    $a7="{SHA}/pbdOXVqxBt0KDqSkmUtNm1zkx8="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}