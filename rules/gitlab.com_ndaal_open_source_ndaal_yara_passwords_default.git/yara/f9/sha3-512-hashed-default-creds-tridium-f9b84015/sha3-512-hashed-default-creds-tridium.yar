rule sha3_512_hashed_default_creds_tridium
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tridium."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="53e9c267afc28f64a89d985fe614ea7f979e1ada72b47d68132b7da052727d5d96eb7285290ff0a0ffc3ccec4c5ce805d6672904e006b77d1c36fc4c5452c0d2"
    $a1="a68a3f4d23e4344236e5652dd765bcbfb6cb8dc22de73ca2c59f5d795a222c8db2e939aeb9bb5f10f74b34d1bd99f83dfb5e5e31b8b17dc9ab2b4c89df8f76b8"
condition:
    ($a0 and $a1)
}