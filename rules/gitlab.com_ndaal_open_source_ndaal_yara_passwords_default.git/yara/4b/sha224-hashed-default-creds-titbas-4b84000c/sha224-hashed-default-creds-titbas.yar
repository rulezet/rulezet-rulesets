rule sha224_hashed_default_creds_titbas
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for titbas."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="dfe91c06d872d631af4c14cca30a6277605ecf2403b6b08065de0620"
    $a1="da870fe5041ff72b2d0ccf747b9fb4ade5003cbdf0d5c2726fb7f4f5"
condition:
    ($a0 and $a1)
}