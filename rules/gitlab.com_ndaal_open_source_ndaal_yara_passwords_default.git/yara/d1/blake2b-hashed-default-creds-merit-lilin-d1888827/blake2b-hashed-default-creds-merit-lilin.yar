rule blake2b_hashed_default_creds_merit_lilin
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for merit_lilin."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a97fac1cb21282a0362a3ab39f5389103b63d752a07e4d6ff2f35d40598ca00d19a7a57fb62ca30f699a4a3b324fa701281733e26dda160e28a8c4c753555a7c"
    $a1="919d61cd295bc9ff01bedfbada1e48fa2f3fe43092c02e63129d234efd7f9dcb33866b1234a0449c9ad3c0b3721adf63ce3f87696001606b7325b652a40faea6"
condition:
    ($a0 and $a1)
}