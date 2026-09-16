rule sha3_512_hashed_default_creds_voicegenie_technologies
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for voicegenie_technologies."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="bc01cefc69c54c31f13d86a416a68211e9e02efb0ac3db1318dd5ea768de73209a7e30ee92d942ea31086fcbdb62a42d2ea7336913628d29e89aea5cf74dd526"
    $a1="bc01cefc69c54c31f13d86a416a68211e9e02efb0ac3db1318dd5ea768de73209a7e30ee92d942ea31086fcbdb62a42d2ea7336913628d29e89aea5cf74dd526"
condition:
    ($a0 and $a1)
}