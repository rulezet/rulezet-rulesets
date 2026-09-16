rule sha3_512_hashed_default_creds_allied
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for allied."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="08576a5ea33e50285f7839faceb8920c99b6623c2da5b134d8ad1df32d18f36f872f7ebdd56b01ee3e53c093dd07a88c487127e798ebd79c15fd4147a8c0d4ca"
    $a1="c36924f3ed986794b7430c969970a95cba7d0e3ec907acaa72377ee8df60c6ba9e4a649dd699f89ebb8258216d52a02fb21f84ef0f8c690bdc8c886d1ad4ecaa"
    $a2="693ad475bc726c9ce3f017b5d84f25135bcac7e3338ca0efc471162644d5c8648c29e00c959aa6a54dccb4fa220524de5ed9b28ee2ad36fbf864ab150b343280"
    $a3="693ad475bc726c9ce3f017b5d84f25135bcac7e3338ca0efc471162644d5c8648c29e00c959aa6a54dccb4fa220524de5ed9b28ee2ad36fbf864ab150b343280"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}