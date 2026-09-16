rule sha3_512_hashed_default_creds_toplayer
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for toplayer."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5cab65850a63a4a7e6a1758f135b640d198751ef45d61757237e0cab56ed38de8a3f384c5b9847ef345936a84a921d1d2023d8605b9c445c6277cc95e207769a"
    $a1="15bdaebc5c86f9bfb3a73a77ccb557874bd5f81c1e01a28c5f366486353039c00f755183b4f02a99cd3ba3873ebdb1295cc9b504121ae4be692af15dad883e16"
condition:
    ($a0 and $a1)
}