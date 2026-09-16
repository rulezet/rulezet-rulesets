rule nthash_hashed_default_creds_main_street_softworks
{
    meta:
        id = "1vVBLhMtYXZKcVyZ7Vctm7"
        fingerprint = "64a484d7514cfe39c6209685cd15038573e5e5c4b26e9060936ef46e7476a49b"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for main_street_softworks."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8846f7eaee8fb117ad06bdd830b7586c"
    $a1="2ba8bb51fd1a5505bd7d9ed344b07b9b"
condition:
    ($a0 and $a1)
}