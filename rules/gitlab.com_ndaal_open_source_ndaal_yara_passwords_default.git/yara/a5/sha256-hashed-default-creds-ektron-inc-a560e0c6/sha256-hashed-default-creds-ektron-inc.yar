rule sha256_hashed_default_creds_ektron_inc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ektron_inc."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="2f0177192e8bdee58fd3d5e4479c148d52b55d3f0205f5d9b17973aa261277c2"
    $a1="2f0177192e8bdee58fd3d5e4479c148d52b55d3f0205f5d9b17973aa261277c2"
    $a2="8dfeea858fb7a73674d0ed862861599283e6c839d214060b9d8291e9086cad52"
    $a3="4cf6829aa93728e8f3c97df913fb1bfa95fe5810e2933a05943f8312a98d9cf2"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}