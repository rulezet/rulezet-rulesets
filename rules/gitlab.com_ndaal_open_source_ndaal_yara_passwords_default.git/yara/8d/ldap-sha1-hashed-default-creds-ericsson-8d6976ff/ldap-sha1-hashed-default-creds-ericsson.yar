rule ldap_sha1_hashed_default_creds_ericsson
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ericsson."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}OqJFYuXdvAL3NU0EzmjgmDyh73s="
    $a1="{SHA}OqJFYuXdvAL3NU0EzmjgmDyh73s="
    $a2="{SHA}dQXWSlTgYbes1UzNWLSdxDUAtjU="
    $a3="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a4="{SHA}kgBezzeI+uqDRqeRn7oCMhiFYas="
    $a5="{SHA}GtaSKFdQtYttjhs6zftkmHS2ulA="
    $a6="{SHA}t4DSUqEsjEcgmcWJ1ymm1gon3Hs="
    $a7="{SHA}t4DSUqEsjEcgmcWJ1ymm1gon3Hs="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}