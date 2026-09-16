rule sha3_384_hashed_default_creds_atlassian_confluence
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for atlassian_confluence."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5158faaa8b26380933745f3d278fd2692e07c81b6fde221f7b885d4c5de144b919dd79a0c185c7e4a99be0680557b221"
    $a1="415ce7cb2d68c1c20baeb36868e9864cbb876021083fa3c70db14abc4800038522ec728c5e0560dce589fa2e6fdc6768"
condition:
    ($a0 and $a1)
}