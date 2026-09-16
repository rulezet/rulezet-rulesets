rule blake2b_hashed_default_creds_cisco_systems_general
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for cisco_systems_general."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="86bf1a207cac134ce813d3c76492271f0322dfe2de8fdeefe541e08bd43dd628610ebbd57ae0c53eb931d6c9c27c11c32d3503d4552952d7808bc9d2d796d804"
    $a1="86bf1a207cac134ce813d3c76492271f0322dfe2de8fdeefe541e08bd43dd628610ebbd57ae0c53eb931d6c9c27c11c32d3503d4552952d7808bc9d2d796d804"
condition:
    ($a0 and $a1)
}