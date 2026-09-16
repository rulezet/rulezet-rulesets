rule ldap_sha1_hashed_default_creds_amx
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for amx."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}PKz9nH+5y0y56X+VEH5eVr8CDF0="
    $a1="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a2="{SHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g="
    $a3="{SHA}s6ypLHk+4OmxqbCl9fwETgUUDfM="
    $a4="{SHA}KGube1CrieM5e031QAIbUx9Ff38="
    $a5="{SHA}3Hbp8MAAbo+RngxRXGbbujmC94U="
    $a6="{SHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g="
    $a7="{SHA}9N6AT6QlUcsk3+81KfBFSG76ipw="
    $a8="{SHA}PKz9nH+5y0y56X+VEH5eVr8CDF0="
    $a9="{SHA}Tnr+vPuuAAsix8heVWD4mioCgLQ="
    $a10="{SHA}NWdeaPS1r3uZXZIFrQ/EOELxZFA="
    $a11="{SHA}NWdeaPS1r3uZXZIFrQ/EOELxZFA="
    $a12="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a13="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a14="{SHA}p8ngEWmPCqw9QrPyqgj/Q1aPopE="
    $a15="{SHA}HtojdYvp425eDSpqh95YSqygGT8="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}