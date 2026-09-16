rule ldap_md5_hashed_default_creds_kodak
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for kodak."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}c6z/bKqx00VPEbnUyKzcSQ=="
    $a1="{MD5}NGWs2ZbKs+bPBjce9JuGqA=="
    $a2="{MD5}c6z/bKqx00VPEbnUyKzcSQ=="
    $a3="{MD5}03Mk0UCz9NayQK82Bi9NXA=="
    $a4="{MD5}c6z/bKqx00VPEbnUyKzcSQ=="
    $a5="{MD5}QYVgtbrTUpuLpDjRt/2L3Q=="
    $a6="{MD5}MZ9NJuPFNrXdhxuyxS4xeA=="
    $a7="{MD5}Pda5Jl/xjzHcMN9ZMEsMpw=="
    $a8="{MD5}wrp+eFxJBQ9I2pqsxFwrhQ=="
    $a9="{MD5}wrp+eFxJBQ9I2pqsxFwrhQ=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}