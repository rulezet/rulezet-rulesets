rule sha3_384_hashed_default_creds_cisco_systems_general
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for cisco_systems_general."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c42b311c9a806f1a08d98b449d28ee68e0e6b6121a3d040f12bc24401693c2915936ef1427013ed49b8a9af8f4af444b"
    $a1="c42b311c9a806f1a08d98b449d28ee68e0e6b6121a3d040f12bc24401693c2915936ef1427013ed49b8a9af8f4af444b"
condition:
    ($a0 and $a1)
}