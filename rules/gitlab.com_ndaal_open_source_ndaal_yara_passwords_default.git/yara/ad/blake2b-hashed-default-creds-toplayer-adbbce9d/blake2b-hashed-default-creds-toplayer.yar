rule blake2b_hashed_default_creds_toplayer
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for toplayer."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c8e38b2eafef907f27a1a4202b4b8a4be3c50a4fc4e9f52099cdf14f07ca7e97df599993bcd3a6168916360247c4d5a42b2772b82438cdbfda86184c9d33b8a1"
    $a1="b545816449da80858876774b3b4c2a7ff96b033303aee0159cff6ef46acd8f5c4293304ce736d98754f03e737075200087738cbb5aedec1d8bfd457ca653761f"
condition:
    ($a0 and $a1)
}