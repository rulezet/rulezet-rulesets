rule ldap_sha1_hashed_default_creds_d_link
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for d_link."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a1="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a2="{SHA}cRDtpNCeBiql5KOQsKVyrA0sAiA="
    $a3="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a4="{SHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g="
    $a5="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a6="{SHA}53kW/nBtdaWILmKTtM9L4cfb9IU="
    $a7="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a8="{SHA}uqpnqgEgB9Gy0UceWLcZyKbO8to="
    $a9="{SHA}Fs64g2/uu6s4mUl/MYlcw3+vyaU="
    $a10="{SHA}YcmysX23eieEG77qv/kjRIsPY4g="
    $a11="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a12="{SHA}4aR6mC97fJPjZfMBilXlNuhl7lg="
    $a13="{SHA}4aR6mC97fJPjZfMBilXlNuhl7lg="
    $a14="{SHA}l7qUrCymKtlOOeD09kUSQdHSuws="
    $a15="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a16="{SHA}lURids36/zoDoivmrWCF5vcSwAQ="
    $a17="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a18="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a19="{SHA}1yv6gX/aDfhsXFu5GM7FerswFy4="
    $a20="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a21="{SHA}3Hbp8MAAbo+RngxRXGbbujmC94U="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21)
}