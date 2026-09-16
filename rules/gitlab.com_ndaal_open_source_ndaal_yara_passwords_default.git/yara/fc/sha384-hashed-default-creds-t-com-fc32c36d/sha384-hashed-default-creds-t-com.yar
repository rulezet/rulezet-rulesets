rule sha384_hashed_default_creds_t_com
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for t_com."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7a25c3751cb99ed6a857e55fdee8bebea6cce9972bccafeba756925cacc73cdb0dada14d8ebb432fa00f54408029a59b"
    $a1="589d0f5f0de1765831ff140d5489f1374d0f388958ad525216e46cd04ac1e16254a5ce5b3cf6d33a7077d2f7ae8d6178"
condition:
    ($a0 and $a1)
}