rule sha512_hashed_default_creds_cisco_aironet_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for cisco_aironet_ssh."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="734577c6e2a923caee555c9b4699f15e1df4a32c6e68766cbca81f4c5fb710f79fda29e376e0ce7b139ec451b7de9075adf8b6b6cc0469ddab29c903fec9483e"
    $a1="734577c6e2a923caee555c9b4699f15e1df4a32c6e68766cbca81f4c5fb710f79fda29e376e0ce7b139ec451b7de9075adf8b6b6cc0469ddab29c903fec9483e"
condition:
    ($a0 and $a1)
}