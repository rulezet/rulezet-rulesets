rule blake2b_hashed_default_creds_netgenesis
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for netgenesis."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c59cf1d6caf5a2730e766d00726654168406338ad36c9a5a1b2d213c70758a682ca6add368afab42aac1845b262cd5122b069707856fe0f09786b67ec1e8c3a3"
    $a1="c59cf1d6caf5a2730e766d00726654168406338ad36c9a5a1b2d213c70758a682ca6add368afab42aac1845b262cd5122b069707856fe0f09786b67ec1e8c3a3"
condition:
    ($a0 and $a1)
}