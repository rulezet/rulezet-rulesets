rule sha3_224_hashed_default_creds_cisco_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for cisco_ssh."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="078af1b167057e4c232bc97bb9aa8f9600e559400374f78c74a9e842"
    $a1="078af1b167057e4c232bc97bb9aa8f9600e559400374f78c74a9e842"
    $a2="078af1b167057e4c232bc97bb9aa8f9600e559400374f78c74a9e842"
    $a3="3e7cf6ccb212cddfe99cd22f7d64667033ef35354acead16cf9955ec"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}