rule ldap_sha1_hashed_default_creds_mitel
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mitel."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g="
    $a1="{SHA}MX8edh8vqo2ngaR2K53MLFytIJo="
    $a2="{SHA}48u6iIP+dGxuNXg8lAS0vAx+6es="
    $a3="{SHA}L8QtN/7iyB12fgn7KYtwx0iUD4Y="
    $a4="{SHA}pLVC7Tyc/G/QyetxOiwP30b1grY="
    $a5="{SHA}MX8edh8vqo2ngaR2K53MLFytIJo="
    $a6="{SHA}S6+vlh2KeT6+yxWA64SSfP6eNWw="
    $a7="{SHA}L8QtN/7iyB12fgn7KYtwx0iUD4Y="
    $a8="{SHA}W7afddIWw3aOpFVB9H/x/dTC9nc="
    $a9="{SHA}MX8edh8vqo2ngaR2K53MLFytIJo="
    $a10="{SHA}GpuVCLYAO2jd/gOpyMvEvUOIM5s="
    $a11="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}