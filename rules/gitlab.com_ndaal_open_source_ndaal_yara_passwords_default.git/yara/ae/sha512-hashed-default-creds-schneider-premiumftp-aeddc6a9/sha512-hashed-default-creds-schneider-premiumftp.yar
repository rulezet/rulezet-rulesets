rule sha512_hashed_default_creds_schneider_premiumftp
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for schneider_premiumftp."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e36ac69210f52ff081cf7e811a791f766e6d56a960ef58ad08447ff60fe9c6ee58bccea8dedb04f4bb30c2d4c26dea2a43908970d1d5968aa1555626d0c66c1e"
    $a1="6162eb4b9377a7c411410c77e310652d31da64a51df77d3b5713f4b9291923fac30c67b26e9f544643957c7ebc5424edbf44a9b563e05ef74917d39ce3d4529a"
condition:
    ($a0 and $a1)
}