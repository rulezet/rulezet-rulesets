rule sha224_hashed_default_creds_glftpd
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for glftpd."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e3cafd232d07f28178ec9e1e92e2ebb1c03ecc24e2f67f81079f891e"
    $a1="e3cafd232d07f28178ec9e1e92e2ebb1c03ecc24e2f67f81079f891e"
condition:
    ($a0 and $a1)
}