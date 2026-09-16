rule sha3_512_hashed_default_creds_allied_telesyn
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for allied_telesyn."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c36924f3ed986794b7430c969970a95cba7d0e3ec907acaa72377ee8df60c6ba9e4a649dd699f89ebb8258216d52a02fb21f84ef0f8c690bdc8c886d1ad4ecaa"
    $a1="c36924f3ed986794b7430c969970a95cba7d0e3ec907acaa72377ee8df60c6ba9e4a649dd699f89ebb8258216d52a02fb21f84ef0f8c690bdc8c886d1ad4ecaa"
    $a2="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a3="c36924f3ed986794b7430c969970a95cba7d0e3ec907acaa72377ee8df60c6ba9e4a649dd699f89ebb8258216d52a02fb21f84ef0f8c690bdc8c886d1ad4ecaa"
    $a4="08576a5ea33e50285f7839faceb8920c99b6623c2da5b134d8ad1df32d18f36f872f7ebdd56b01ee3e53c093dd07a88c487127e798ebd79c15fd4147a8c0d4ca"
    $a5="23da8a9053fc47ed8afb004dd1559061050ddc8ddf1d38f0b02566b9a2f6962345e22bd807f576775b07cd8a63aafc583fe7747bd73f0633e7eb83791d3967e9"
    $a6="08576a5ea33e50285f7839faceb8920c99b6623c2da5b134d8ad1df32d18f36f872f7ebdd56b01ee3e53c093dd07a88c487127e798ebd79c15fd4147a8c0d4ca"
    $a7="c36924f3ed986794b7430c969970a95cba7d0e3ec907acaa72377ee8df60c6ba9e4a649dd699f89ebb8258216d52a02fb21f84ef0f8c690bdc8c886d1ad4ecaa"
    $a8="693ad475bc726c9ce3f017b5d84f25135bcac7e3338ca0efc471162644d5c8648c29e00c959aa6a54dccb4fa220524de5ed9b28ee2ad36fbf864ab150b343280"
    $a9="693ad475bc726c9ce3f017b5d84f25135bcac7e3338ca0efc471162644d5c8648c29e00c959aa6a54dccb4fa220524de5ed9b28ee2ad36fbf864ab150b343280"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}