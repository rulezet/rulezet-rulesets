rule sha384_hashed_default_creds_conitec
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for conitec."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="50fa38f83bf0acec1e6f9486a6e00f2abced05b451ac26fc91adabe8c9173ce100071ba42932048c080ef21982a7cb39"
    $a1="596ebba0a848db6019d9e4a6e66222d174cb710d9c0984e0e3b881ce1fda25389aedff13e06d82db76661093e712f5db"
condition:
    ($a0 and $a1)
}