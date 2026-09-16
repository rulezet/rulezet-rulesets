rule ldap_sha1_hashed_default_creds_hp
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for hp."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g="
    $a1="{SHA}3Hbp8MAAbo+RngxRXGbbujmC94U="
    $a2="{SHA}44tJAuy4GYKm5TOu95PHuG7kJoA="
    $a3="{SHA}xl+Z+MU3atrd3EbVy89XYvnlXrc="
    $a4="{SHA}EkRIVZ9HdZl5HyBo8THb5smk5Fc="
    $a5="{SHA}+0NNOGmIMqWZ5B4+xVSV+IbijLs="
    $a6="{SHA}qC4SboYhQdDsuADL2Jw03lTrO4c="
    $a7="{SHA}+0NNOGmIMqWZ5B4+xVSV+IbijLs="
    $a8="{SHA}75ke9gfmnf3RGYNDt2FBqPtMI18="
    $a9="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a10="{SHA}8iMdKHHmkKKZVwT3ope9e8ZL5yA="
    $a11="{SHA}5HubECEDSla31fcNktBIFSTnj2k="
    $a12="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a13="{SHA}HtojdYvp425eDSpqh95YSqygGT8="
    $a14="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a15="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a16="{SHA}lm4E2SVQDmw17Y+oAo8z+jvbncs="
    $a17="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}