rule sha3_384_hashed_default_creds_opengts_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for opengts_mssql."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="25f6418375b2d7125fea13bf096ec3429d239faee52394f73ef5d1b65b30bd0b068b3d6c0551a6a0b64b767dea51d8a1"
    $a1="583b231df453bd0a71c72f24f95fa19df5ac3629da17281df33145f3331213c43a7dc7b4481b58967431e63d79be6302"
condition:
    ($a0 and $a1)
}