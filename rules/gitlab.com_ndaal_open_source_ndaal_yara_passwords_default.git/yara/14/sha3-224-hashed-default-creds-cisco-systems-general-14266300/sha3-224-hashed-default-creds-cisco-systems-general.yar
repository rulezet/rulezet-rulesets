rule sha3_224_hashed_default_creds_cisco_systems_general
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for cisco_systems_general."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="078af1b167057e4c232bc97bb9aa8f9600e559400374f78c74a9e842"
    $a1="078af1b167057e4c232bc97bb9aa8f9600e559400374f78c74a9e842"
condition:
    ($a0 and $a1)
}