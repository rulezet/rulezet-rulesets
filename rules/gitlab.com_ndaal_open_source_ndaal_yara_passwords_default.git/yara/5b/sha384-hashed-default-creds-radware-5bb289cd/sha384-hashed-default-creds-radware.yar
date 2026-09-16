rule sha384_hashed_default_creds_radware
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for radware."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="50acf6854ff049011cd9187fd75de3d3f3f58c1b474fbf263b9be441811912ab269f93ee2020b1a19cfb9996243b506b"
    $a1="50acf6854ff049011cd9187fd75de3d3f3f58c1b474fbf263b9be441811912ab269f93ee2020b1a19cfb9996243b506b"
    $a2="5d51df127cb09685d20f2808a179325f18d41df55a6b65a3b0f982ce6377b79c06877eb66415bb4c9547d7ca0ccca642"
    $a3="5d51df127cb09685d20f2808a179325f18d41df55a6b65a3b0f982ce6377b79c06877eb66415bb4c9547d7ca0ccca642"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}