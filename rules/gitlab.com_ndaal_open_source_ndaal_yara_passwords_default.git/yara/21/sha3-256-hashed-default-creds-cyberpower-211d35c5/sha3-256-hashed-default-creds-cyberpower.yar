rule sha3_256_hashed_default_creds_cyberpower
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for cyberpower."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="aef1bbdfc8b0e6020cb5f69d892761ecd1738b3bab3823ca7b4f1df6c5eed472"
    $a1="aef1bbdfc8b0e6020cb5f69d892761ecd1738b3bab3823ca7b4f1df6c5eed472"
    $a2="aef1bbdfc8b0e6020cb5f69d892761ecd1738b3bab3823ca7b4f1df6c5eed472"
    $a3="df134c3c5cd073714cb9e7ddc422b9c863cd7f44a8b6ac78b0afc7aee5e54011"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}