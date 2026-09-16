rule blake2s_hashed_default_creds_cassandra
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for cassandra."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="db7deb68b6318d965e54d001c61878dcceed4c85e77e3419d5a8ccf8899e6d57"
    $a1="db7deb68b6318d965e54d001c61878dcceed4c85e77e3419d5a8ccf8899e6d57"
condition:
    ($a0 and $a1)
}