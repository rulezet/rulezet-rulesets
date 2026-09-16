rule ldap_sha1_hashed_default_creds_smc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for smc."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}zyHYWEMAJjrVnYFTIXwv4+h/8v0="
    $a1="{SHA}uGydMy+A1orjwnTJhCGfu5mate8="
    $a2="{SHA}T/3U206xvVhlqNO3qc2/tYdGXfc="
    $a3="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a4="{SHA}zyHYWEMAJjrVnYFTIXwv4+h/8v0="
    $a5="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a6="{SHA}7ONid1ADqizEUu0A08H6Xg9793o="
    $a7="{SHA}jxmPrYXBreLB+ldRWHJmcteJ7uo="
    $a8="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a9="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a10="{SHA}zyHYWEMAJjrVnYFTIXwv4+h/8v0="
    $a11="{SHA}HtojdYvp425eDSpqh95YSqygGT8="
    $a12="{SHA}vXHHG06gJXHJ/gWLfpsqouoszKk="
    $a13="{SHA}Aofm9puNYIoeTkWCUZ9BVNGgRAg="
    $a14="{SHA}9Y8cm7vO0kGYGKCiFR40CtzAzIs="
    $a15="{SHA}Tnr+vPuuAAsix8heVWD4mioCgLQ="
    $a16="{SHA}X1Ag1n0LYz5Z+BwKk1P8Z/MosN4="
    $a17="{SHA}dQXWSlTgYbes1UzNWLSdxDUAtjU="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}