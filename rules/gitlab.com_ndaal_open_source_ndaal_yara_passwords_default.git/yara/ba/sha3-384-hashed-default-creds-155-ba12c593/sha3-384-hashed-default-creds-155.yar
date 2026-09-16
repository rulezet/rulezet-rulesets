rule sha3_384_hashed_default_creds_155
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for 155."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1f2b7e1bfe94444e3f1e34f8aa38591a2650c3a782982036dd7fc3f1872df5b07142b703d57b3d126308f87550c2e5f0"
    $a1="4e5a6f0fba604547745375eb56ccc6f7cecb54dfcbb0b3b65813667ed0ad417ab61e9be79f05ad44e85b29dde2b3fbe1"
    $a2="3a742726566f6d65b11330667491a565ca4f74afa94ff04ef0e13b98fec6b50ec9efe4f779d45f90ce883367841ee691"
    $a3="3a742726566f6d65b11330667491a565ca4f74afa94ff04ef0e13b98fec6b50ec9efe4f779d45f90ce883367841ee691"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}