rule nthash_hashed_default_creds_ncr
{
    meta:
        id = "1LlJ5Ank9jDugZR2lFnGDu"
        fingerprint = "5419f711f49c263a56a8ffaef9b101b068b22b6424e4e8ba5d82b08516c37a6b"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ncr."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b6982d4aedb6c39b2ac52c9f99c04198"
    $a1="b6982d4aedb6c39b2ac52c9f99c04198"
condition:
    ($a0 and $a1)
}