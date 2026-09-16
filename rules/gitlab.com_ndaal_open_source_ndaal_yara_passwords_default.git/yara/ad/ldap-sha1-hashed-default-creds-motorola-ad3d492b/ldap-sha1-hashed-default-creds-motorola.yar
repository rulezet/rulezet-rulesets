rule ldap_sha1_hashed_default_creds_motorola
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for motorola."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}d+sdtsuBs8sIjTareq6PIw3Pqig="
    $a1="{SHA}rVlPF9ZX7yHVnyAS9DiNi2U1LV4="
    $a2="{SHA}UegixQzGLNvbhQpDnqdbbUWsSHs="
    $a3="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a4="{SHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g="
    $a5="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a6="{SHA}JvWArg78aQee2aa+6g4wKIrZARk="
    $a7="{SHA}TPW8Wb7p4cRMYlS1+E5/BmvY5f4="
    $a8="{SHA}cpRKF8Bu7b3YPWv9jZmZ6KIjZjc="
    $a9="{SHA}VdJYAPuCuimiZ8kyMAqqihl2e3U="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}