rule blake2b_hashed_default_creds_ewon
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ewon."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="42373117c429fcf616c460f81e3c2e20c8718c3793508c65dd7692f21a1eede776e782371d964b0c89acadbe6dba8200950443e5cbc99165ae22bd9c4d744ebb"
    $a1="42373117c429fcf616c460f81e3c2e20c8718c3793508c65dd7692f21a1eede776e782371d964b0c89acadbe6dba8200950443e5cbc99165ae22bd9c4d744ebb"
condition:
    ($a0 and $a1)
}