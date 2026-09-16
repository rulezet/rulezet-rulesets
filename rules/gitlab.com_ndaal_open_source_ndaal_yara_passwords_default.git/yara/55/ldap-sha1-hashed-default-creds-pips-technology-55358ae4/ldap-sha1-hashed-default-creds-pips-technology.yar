rule ldap_sha1_hashed_default_creds_pips_technology
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for pips_technology."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}zqyQddKZzDdZ78YeGuMVwpQHb38="
    $a1="{SHA}zqyQddKZzDdZ78YeGuMVwpQHb38="
    $a2="{SHA}9MYgqVZWste4wP7XYD7WS8AsyVI="
    $a3="{SHA}9MYgqVZWste4wP7XYD7WS8AsyVI="
    $a4="{SHA}jU2N1z1fHUBNJd0w2yXZG4rs4nY="
    $a5="{SHA}jU2N1z1fHUBNJd0w2yXZG4rs4nY="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}