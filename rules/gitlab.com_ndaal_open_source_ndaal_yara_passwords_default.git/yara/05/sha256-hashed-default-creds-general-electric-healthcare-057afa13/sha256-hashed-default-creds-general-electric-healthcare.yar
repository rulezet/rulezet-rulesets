rule sha256_hashed_default_creds_general_electric_healthcare
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for general_electric_healthcare."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a1="c1c224b03cd9bc7b6a86d77f5dace40191766c485cd55dc48caf9ac873335d6f"
    $a2="c9bb503300194d3202e27f4590b1a6f3575fa8ff9d8b2155ad8df932bf0f3778"
    $a3="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a4="c9bb503300194d3202e27f4590b1a6f3575fa8ff9d8b2155ad8df932bf0f3778"
    $a5="c9bb503300194d3202e27f4590b1a6f3575fa8ff9d8b2155ad8df932bf0f3778"
    $a6="d768c1ee678644dce773dd6f7078ddf89ee4ee9ea0d270cc66d196a4b399391b"
    $a7="4813494d137e1631bba301d5acab6e7bb7aa74ce1185d456565ef51d737677b2"
    $a8="a2e0e7ff5cd818186b05ff07c9cb646e90d6b38bd7a583425613871ac4132e6b"
    $a9="48886fa89ff7ec55343263a088bd1ebf0e798b7646d99be34d8c34d1683b5aa0"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}