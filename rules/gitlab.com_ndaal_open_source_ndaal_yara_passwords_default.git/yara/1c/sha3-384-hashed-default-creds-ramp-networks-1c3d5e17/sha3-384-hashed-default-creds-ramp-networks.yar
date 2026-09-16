rule sha3_384_hashed_default_creds_ramp_networks
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ramp_networks."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="af49a390faf8c3d40e73a61d894a97d41a7d29e10d5e376d848cdd825a16b065504a3974900c189d4d4170b3d64cf161"
    $a1="bdb5fb19247d8419edaf730b1f6733bb17280c794449285e55d7d5d539b38b3dd427451fa52b9028b1f8119674d31794"
condition:
    ($a0 and $a1)
}