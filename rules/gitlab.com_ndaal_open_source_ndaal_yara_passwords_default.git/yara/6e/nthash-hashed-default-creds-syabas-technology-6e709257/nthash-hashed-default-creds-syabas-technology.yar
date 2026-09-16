rule nthash_hashed_default_creds_syabas_technology
{
    meta:
        id = "1iIIwjL5QxO1KPYdSS6aPF"
        fingerprint = "eb4178374ca339b867d8888e623f3debd6a11125383ff773f9957f3269a8193f"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for syabas_technology."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7ce21f17c0aee7fb9ceba532d0546ad6"
    $a1="9e427414009e765b30af480fcbb532fa"
    $a2="7ce21f17c0aee7fb9ceba532d0546ad6"
    $a3="4a6e758d82a49ae433f2317927ae7bb6"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}