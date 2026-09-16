rule sha256_hashed_default_creds_dvb
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for dvb."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="660c37442e010d523dd3e5f063881cb9d105eb7947ea391a7a539e4c6eaf92b4"
    $a1="d07822d74132acf5f284e2c39f9c549ac635c78fb77b1153c40f82436a9ed237"
    $a2="c8a88e9f8851c5aea1cc0e3dbc6d7b91ed905cb6f22b1e8ced66ecf6b2f53f30"
    $a3="4813494d137e1631bba301d5acab6e7bb7aa74ce1185d456565ef51d737677b2"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}