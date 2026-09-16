rule sha256_hashed_default_creds_xylan
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for xylan."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
    $a1="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a2="78b49fb2cc2d2ed6c1bb8383b3d267b3bc623a8a0fb4aff4aa5d3db74c3b4967"
    $a3="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a4="78b49fb2cc2d2ed6c1bb8383b3d267b3bc623a8a0fb4aff4aa5d3db74c3b4967"
    $a5="be3f1b44776624b9c37b661e9711ac1d8f51628b80c33e3b60b6a56fea088c9b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}