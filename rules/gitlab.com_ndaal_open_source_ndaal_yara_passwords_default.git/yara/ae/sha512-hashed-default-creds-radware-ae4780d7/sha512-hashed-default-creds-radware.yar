rule sha512_hashed_default_creds_radware
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for radware."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e40c136d125d5b29d6de7394f2617968aaedd0d9f6af63748e3d35711de1b9a2fb5b63899b1bc8bdaf243625ccb2f003d11bacc9fe0ad1490472add97ad769d3"
    $a1="e40c136d125d5b29d6de7394f2617968aaedd0d9f6af63748e3d35711de1b9a2fb5b63899b1bc8bdaf243625ccb2f003d11bacc9fe0ad1490472add97ad769d3"
    $a2="0fcd307f76f7ab45e0e49269f6787552143f9652b394a2720e8d61a754841d815fcd9b05c7613ee746ef7e3ab5ac17421e08f3ff8d63f6a906177266fa0b2f69"
    $a3="0fcd307f76f7ab45e0e49269f6787552143f9652b394a2720e8d61a754841d815fcd9b05c7613ee746ef7e3ab5ac17421e08f3ff8d63f6a906177266fa0b2f69"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}