rule sha3_512_hashed_default_creds_deerfield
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for deerfield."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9a79e6179d0dfc10bfd3b7c57077d4512fc878816c8b44e2a3a52dd7f6db18a29c0149c087d9915bbce49f013bc5ae143b9fefcf17bdb56d6215a0ab69abebdf"
    $a1="08ee6a08899afacb95d318e1c1b65963826e12e4a07830a38259c492ef889ba48d8f537b2fbc44eea8e4921e29fe9ff6c3e08c55a416f0182dae3ec3529329a5"
condition:
    ($a0 and $a1)
}