rule sha384_hashed_default_creds_general_electric_healthcare
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for general_electric_healthcare."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a1="cb25ed2781626b3ab0c1de865e7cc7e6db8908f6d6046d96a284c8f95e1edee6da77588358648e0508a7725f1a777778"
    $a2="ca9e49474f5e878cadaaf494ee85038fc6cf1230e9ea9e88fb863343a3ffd8c9e5747de0b6ef599bf32e00f27937b67c"
    $a3="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a4="ca9e49474f5e878cadaaf494ee85038fc6cf1230e9ea9e88fb863343a3ffd8c9e5747de0b6ef599bf32e00f27937b67c"
    $a5="ca9e49474f5e878cadaaf494ee85038fc6cf1230e9ea9e88fb863343a3ffd8c9e5747de0b6ef599bf32e00f27937b67c"
    $a6="f7e9a7ac5176bdd2e265a156754c78b5f99e5b66d6880a7ad8ad44e198f30d5c3ca61b0bbe5726a8a36bca1b00fd6e68"
    $a7="7ed8c2c790aa83d6c3e404b5368f6832c18d46a0e98b9c7a7a5e3ef823e2c9f0e310abbf6f7ea9d9d883ccb64ec2736a"
    $a8="42d006cecba897949868c11d26e729a902b4968aa40c786ffc0c279301ab409a4b9219fc63ef3498a99cabfee9ffe58d"
    $a9="ab665571d308b61a9967706fde1299e967779aaab172b73ab8f02ae912d6a93e4d904389e07db532bc9725d4b1333f4c"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}