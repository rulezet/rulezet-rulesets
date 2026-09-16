rule blake2b_hashed_default_creds_gonet
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for gonet."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a8770f3f7909e76148ddcc756c3f6e76742f4b5099fb3a2ead91d4e28527194f4384ef8aa4aae1eb8685001282b577df12dc17def7f6544f6d2f8af54ee97fbc"
    $a1="e5c631f43d4c8ba14ad32c3bdbf4be11a76c7dee9845495e81a9aaf4fb3ada0380843c386f7a4510edc834f79ac658706677c8a0c20c82c42fb6c33243e111db"
condition:
    ($a0 and $a1)
}