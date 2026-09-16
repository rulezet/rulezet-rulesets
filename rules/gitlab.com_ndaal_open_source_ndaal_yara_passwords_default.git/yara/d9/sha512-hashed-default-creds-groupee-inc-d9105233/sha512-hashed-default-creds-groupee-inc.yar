rule sha512_hashed_default_creds_groupee_inc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for groupee_inc."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e8ced854720eb556137b52043ce832da9b04a4a6290521e890afb8148d16a16a4af2be315cadfa322b78b7a18d97285145dfbae9a26a8acea0a05d2fa5fab6cf"
    $a1="8e0a8fb22f8975d4dfc02e802e431cc896e30adc4c4d9e46efe87584c6a33028a6ab1ed219095afbb8f5e7117dcc469d7625499c270dee6e84a4b2dee9247d38"
condition:
    ($a0 and $a1)
}