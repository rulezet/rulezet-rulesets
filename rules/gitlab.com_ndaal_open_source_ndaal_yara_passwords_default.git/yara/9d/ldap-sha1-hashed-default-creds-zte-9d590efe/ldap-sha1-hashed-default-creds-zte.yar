rule ldap_sha1_hashed_default_creds_zte
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for zte."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}kVbm+eYXzUqHFK9fj2sqUB+2sR8="
    $a1="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a2="{SHA}6FJWYewOh82gVpfm4fBQp+xrLoo="
    $a3="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a4="{SHA}Et6pb+wgWTVmq3VpLJlJWWgzrck="
    $a5="{SHA}Et6pb+wgWTVmq3VpLJlJWWgzrck="
    $a6="{SHA}nojrAjmaiUfK0jlbAVldhIx6HIc="
    $a7="{SHA}hExZC6HvN1fYisSVG/Jp0XYVyHo="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}