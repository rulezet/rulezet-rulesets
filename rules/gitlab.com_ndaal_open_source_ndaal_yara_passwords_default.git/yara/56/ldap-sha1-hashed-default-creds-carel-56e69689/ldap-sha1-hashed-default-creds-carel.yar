rule ldap_sha1_hashed_default_creds_carel
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for carel."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}f149Ll0oynDQmreXFP0skCki5WM="
    $a1="{SHA}3Hbp8MAAbo+RngxRXGbbujmC94U="
    $a2="{SHA}eNtjY2DLQ2AZUXTbC1zrtHyGbhM="
    $a3="{SHA}YStDYnw4AOiTMQa2hUjCm/C/88M="
    $a4="{SHA}FwKAyaqbY280wCxiNjkNhf2pO9M="
    $a5="{SHA}NWdeaPS1r3uZXZIFrQ/EOELxZFA="
    $a6="{SHA}C3sF3lB0Gs6ULKYOHQfEWoavuNs="
    $a7="{SHA}hZwS68tLq/E6axblDrTs9ybuOAM="
    $a8="{SHA}G1+KKl2Ks3t/uqY/UyAKotfGEsY="
    $a9="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a10="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a11="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a12="{SHA}hsTsnA8iS9gMbXzKhTflRk+ZZr8="
    $a13="{SHA}qyv/UV35yjX8fKh0MKbFZCZT5Lk="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}