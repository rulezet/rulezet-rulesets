rule ldap_sha1_hashed_default_creds_us_robotics
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for us_robotics."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}jLIjfQZ5yojbZGTqxg2pY0VROWQ="
    $a1="{SHA}3Hbp8MAAbo+RngxRXGbbujmC94U="
    $a2="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a3="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a4="{SHA}W9zTwNTSSuPnGztFKgJMYyTH5Ls="
    $a5="{SHA}W9zTwNTSSuPnGztFKgJMYyTH5Ls="
    $a6="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a7="{SHA}3Hbp8MAAbo+RngxRXGbbujmC94U="
    $a8="{SHA}jLIjfQZ5yojbZGTqxg2pY0VROWQ="
    $a9="{SHA}MiRE07tSw0H0KcoEVPKS3CQvMVs="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}