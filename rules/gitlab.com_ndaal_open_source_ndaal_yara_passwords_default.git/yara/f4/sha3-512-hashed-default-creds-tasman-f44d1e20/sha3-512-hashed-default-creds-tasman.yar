rule sha3_512_hashed_default_creds_tasman
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tasman."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f390e84c4e1b582a9bbff9248424f26cf2ec34d09ab7f4fff72ee1fd83aec8f583f54260920ee63251d9ab125e08d78b47df95abb1b556dc02aae0c994c1ad7e"
    $a1="0f486dd98c5dcfe4e62421e8c8aee6dfb031af24357c101bc2ddeb2301f6e2dfe82a1c35f5301c9d6ad21c6e837eb4365905da365e3840655ce64dfed65b3b4f"
condition:
    ($a0 and $a1)
}