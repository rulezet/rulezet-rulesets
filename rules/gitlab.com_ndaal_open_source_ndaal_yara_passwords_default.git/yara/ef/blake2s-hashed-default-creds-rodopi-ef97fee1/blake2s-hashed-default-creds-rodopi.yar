rule blake2s_hashed_default_creds_rodopi
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for rodopi."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b0d4332cbf6846f795f304eebf370186b213f70e864ce4d075aea05885aa5306"
    $a1="b0d4332cbf6846f795f304eebf370186b213f70e864ce4d075aea05885aa5306"
    $a2="6f7b1c074cdb9ff3de37be03ab3e1777231d2a9fcf5898033446f067d431ec4d"
    $a3="6f7b1c074cdb9ff3de37be03ab3e1777231d2a9fcf5898033446f067d431ec4d"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}