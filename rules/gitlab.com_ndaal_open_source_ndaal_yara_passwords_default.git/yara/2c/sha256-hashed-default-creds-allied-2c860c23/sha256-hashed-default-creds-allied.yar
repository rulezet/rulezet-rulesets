rule sha256_hashed_default_creds_allied
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for allied."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="cde48537ca2c28084ff560826d0e6388b7c57a51497a6cb56f397289e52ff41b"
    $a1="6ee4a469cd4e91053847f5d3fcb61dbcc91e8f0ef10be7748da4c4a1ba382d17"
    $a2="68a9bb8989efd73ddfd694dff79181fd2db171a23ad1edfdce6d17a2afe82301"
    $a3="68a9bb8989efd73ddfd694dff79181fd2db171a23ad1edfdce6d17a2afe82301"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}