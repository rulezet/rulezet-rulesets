rule blake2s_hashed_default_creds_ibm_imm_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ibm_imm_web."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="57dc47a9eb9becb8d558024404ab271631aec582eebb5b6076b0ada9ef2de835"
    $a1="d58ed7560e7a0cb80b317d66c3104fe78481ffdb3fe6a49bc8156e2176f79a1a"
condition:
    ($a0 and $a1)
}