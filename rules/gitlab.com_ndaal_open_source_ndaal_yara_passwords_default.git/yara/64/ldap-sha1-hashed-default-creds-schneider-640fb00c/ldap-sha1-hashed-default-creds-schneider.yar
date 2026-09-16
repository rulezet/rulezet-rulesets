rule ldap_sha1_hashed_default_creds_schneider
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for schneider."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}vrxyqX81S2qynmYSHHxgGyhgAhE="
    $a1="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a2="{SHA}cPbUj5TOPnY2u/R0SsB0UJ1nDm8="
    $a3="{SHA}KnF4KBCvOPJWKovcZVslQ1jUFFY="
    $a4="{SHA}dIpiulMTH3+Nu/3i2lYWOmYBO4U="
    $a5="{SHA}P48AD+2QDEoYmpPOSFgoG/s3Dwk="
    $a6="{SHA}O6a+6GU+SKmUWmZ6tzV76wwO9MU="
    $a7="{SHA}pbI/M4ZIy28h4swShOTRt7kwrJc="
    $a8="{SHA}PD5RWQo2ePBuhnvEqNqyIfxF8ug="
    $a9="{SHA}rZqXj+wp/IpWakrKMbGX9snywco="
    $a10="{SHA}brDGEgGpavyZy/GA8cjZPAqf2Mg="
    $a11="{SHA}brDGEgGpavyZy/GA8cjZPAqf2Mg="
    $a12="{SHA}Z+oYFx7ixRzoZy/lGaLp1+0JkWs="
    $a13="{SHA}brDGEgGpavyZy/GA8cjZPAqf2Mg="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}