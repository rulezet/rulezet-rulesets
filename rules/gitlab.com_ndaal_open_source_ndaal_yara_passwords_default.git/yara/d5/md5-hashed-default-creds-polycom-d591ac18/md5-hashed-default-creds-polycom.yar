rule md5_hashed_default_creds_polycom
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for polycom."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="250cf8b51c773f3f8dc8b4be867a9a02"
    $a1="834622a413e3c42c2dd8080c226bee85"
    $a2="1d11d5c3d9f74519486d29845433d29f"
    $a3="834622a413e3c42c2dd8080c226bee85"
    $a4="2d2b96462d029cfb96c3bd185634f96d"
    $a5="200ceb26807d6bf99fd6f4f0d1ca54d4"
    $a6="042e4af7dca5cd093dd1e71775e451e0"
    $a7="21232f297a57a5a743894a0e4a801fc3"
    $a8="efb13c5d92b641a10423401c0745061f"
    $a9="834622a413e3c42c2dd8080c226bee85"
    $a10="250cf8b51c773f3f8dc8b4be867a9a02"
    $a11="21232f297a57a5a743894a0e4a801fc3"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}