rule ldap_sha1_hashed_default_creds_mcafee
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mcafee."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}yzm7VcleyuDXd4QexGhtU8Lz1UI="
    $a1="{SHA}/49cWToB+fzT7UiwmksBPo2PO+c="
    $a2="{SHA}+GW1NiOxIf007lQmx5Llwzr4wic="
    $a3="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a4="{SHA}bVhfc4FI+njc2O7Qxy1VYIJkeDg="
    $a5="{SHA}rs4NtCVMdl5G91lbbbkMUXEiVW0="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}