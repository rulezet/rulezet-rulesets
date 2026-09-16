rule sha384_hashed_default_creds_enterasys
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for enterasys."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="70e37c7ea05439431632b6f111c55cbb14a08a072cdbea5d024eb41262a211c5247112b4664f706ab874d47b215e1dc0"
    $a1="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a2="42558a2167a555f161a6e98ec87fcacb02fa5fb6451874f254f32b3739fa0c7a2c43c4b1b9a117233d96360c1fca06e7"
    $a3="5ff16255d4666e60dc7653c6cf982274e73d0c0c401f7feb28f9dd9e9e649e87805a8153c75c6950d48a8dea2c5c5a62"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}