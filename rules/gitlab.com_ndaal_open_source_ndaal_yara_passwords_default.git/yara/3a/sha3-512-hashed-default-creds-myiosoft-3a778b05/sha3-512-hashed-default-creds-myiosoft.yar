rule sha3_512_hashed_default_creds_myiosoft
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for myiosoft."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a9210a3b1268ce3f2d9b5357dc79c1a4902cb5c5d7244589990263f1bac3d2678854031cc70444921fc6fb11ff9568dabc41a48b6bf3b808e84be58c0df4a881"
    $a1="a9210a3b1268ce3f2d9b5357dc79c1a4902cb5c5d7244589990263f1bac3d2678854031cc70444921fc6fb11ff9568dabc41a48b6bf3b808e84be58c0df4a881"
condition:
    ($a0 and $a1)
}