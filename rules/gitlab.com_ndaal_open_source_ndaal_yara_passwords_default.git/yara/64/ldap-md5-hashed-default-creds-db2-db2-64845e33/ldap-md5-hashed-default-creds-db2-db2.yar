rule ldap_md5_hashed_default_creds_db2_db2
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for db2_db2."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}CifraEgCv9iWO0Ug81wIKw=="
    $a1="{MD5}FyGS7F6xp4k8q70kGGketg=="
    $a2="{MD5}uaJodwdTTWByaijsR9E5OQ=="
    $a3="{MD5}uaJodwdTTWByaijsR9E5OQ=="
    $a4="{MD5}bDRimDXTifPMS0SfLlUfXA=="
    $a5="{MD5}bDRimDXTifPMS0SfLlUfXA=="
    $a6="{MD5}DPlytY75yE9o2Y8eQt8O3A=="
    $a7="{MD5}DPlytY75yE9o2Y8eQt8O3A=="
    $a8="{MD5}PWDtYNwFZjWH944/cHij4A=="
    $a9="{MD5}PWDtYNwFZjWH944/cHij4A=="
    $a10="{MD5}s+0DeIuSKYNPHXq9oXzmcg=="
    $a11="{MD5}PWDtYNwFZjWH944/cHij4A=="
    $a12="{MD5}0xKX0sXvAawbX3StjTyNmg=="
    $a13="{MD5}PWDtYNwFZjWH944/cHij4A=="
    $a14="{MD5}LxxeUZElUAfygzRQxKzbJw=="
    $a15="{MD5}PWDtYNwFZjWH944/cHij4A=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}