rule sha256_hashed_default_creds_opengts_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for opengts_mssql."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ca5eefeb706f0dd49cc433d89e9a32ea2d697632a04f0b86a06639f6b1a3c509"
    $a1="234b5b671f805415ff7f3d26e37f78d1e40ea60fdfa5f61dce7624662afa7307"
condition:
    ($a0 and $a1)
}