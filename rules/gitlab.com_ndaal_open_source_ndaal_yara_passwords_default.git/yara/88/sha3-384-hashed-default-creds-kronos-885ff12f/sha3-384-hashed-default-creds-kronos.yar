rule sha3_384_hashed_default_creds_kronos
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for kronos."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a50c39664eba4988e2eeb20138a14863411501c0f5eac9191197f30877e1267da9b3fead721fe813b6aff277cf432d4f"
    $a1="f91f4efd0c7ec979aeb5ac81a5d529319c1ca0606164bf68f75f62b82c9abcf1b875bd4360e01e385dbecf9e3338d495"
condition:
    ($a0 and $a1)
}