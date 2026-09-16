rule blake2b_hashed_default_creds_cyclades
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for cyclades."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="817897f221b805efdd5de77308528f679cdfdf217c51318e70f0c841d335eed6387140542f8566111dcfc236d66f4233d722404df2065f662a9f7e54e25bdae1"
    $a1="da8d291e0916119783bb03757c6252fb55ea1d51bfb05e3044d676a827ad9afd002fcfdc5706406cb66b61cea06b9ba64f895d7e66b8aedd5bd84182b9b46fe0"
    $a2="2fa59434039f5530c18f6f71e6f26090c44df3ecab18635439067322e8bfacaba84ef2ec1536ad282e3f59f17da70ac606fcea1166492a47422d3136c3589dc1"
    $a3="da23f3a4e096b0816ec2070050eac6cd9243240dad0b5cde6573e41d6852939ac5468aa9d81b5fbe156feb231a069f5afe8a5146630abc7807b1e0dcdaeb049a"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}