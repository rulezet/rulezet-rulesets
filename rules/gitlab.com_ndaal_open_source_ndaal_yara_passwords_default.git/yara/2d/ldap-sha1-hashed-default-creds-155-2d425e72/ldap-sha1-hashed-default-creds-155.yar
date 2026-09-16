rule ldap_sha1_hashed_default_creds_155
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for 155."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}OqM71h3kQwLVAVDyTUh0mO/v+yI="
    $a1="{SHA}MvquysdCEA93U/DB0KoK3QG0BGs="
    $a2="{SHA}yV7kdomgquxww+uVAkRldyLGmx8="
    $a3="{SHA}yV7kdomgquxww+uVAkRldyLGmx8="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}