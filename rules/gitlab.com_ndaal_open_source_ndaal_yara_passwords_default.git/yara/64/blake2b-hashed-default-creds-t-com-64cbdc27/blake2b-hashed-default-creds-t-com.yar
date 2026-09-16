rule blake2b_hashed_default_creds_t_com
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for t_com."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="97639409cd26aa0187e363502f9e8ac8c8df1d29d77e6b1e242e4d778c37de9a67c28ac6df5d06523d9e9c71d05ec4672a11bf22283c33eb1ef9d0a43b5084f0"
    $a1="f9a2525b3b0767c9cb99ee13e93935371017ebd3ccfdb23314a8b67aad425b720e3355c711ed32a7051299eb4a10a75a9951c72e59847e86849f2aa0d8d74e40"
condition:
    ($a0 and $a1)
}