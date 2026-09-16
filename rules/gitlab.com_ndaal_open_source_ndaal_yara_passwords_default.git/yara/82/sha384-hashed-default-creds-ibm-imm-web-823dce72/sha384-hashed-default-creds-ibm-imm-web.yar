rule sha384_hashed_default_creds_ibm_imm_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ibm_imm_web."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="95bb8661afd7e9483a41818e8e87b82952bae3dc0fae7f05a65418a902579907623d806bcf2a99ae4260fe5c5566d015"
    $a1="efe32638d64bd159be83959149ee6c0ef02b4d84d6568e1131a285770d49e46d062748dae2790509abfd834722040f8b"
condition:
    ($a0 and $a1)
}