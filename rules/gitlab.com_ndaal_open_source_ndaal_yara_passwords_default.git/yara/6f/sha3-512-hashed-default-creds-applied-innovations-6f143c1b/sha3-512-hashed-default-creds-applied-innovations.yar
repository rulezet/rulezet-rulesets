rule sha3_512_hashed_default_creds_applied_innovations
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for applied_innovations."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="beacd481df0fdd80e82571ff2e3b2ca8614295670cc809e052fdf0c4d0d301608b37578ce9b92e74c3f0c62833348a47c453be4a771aee860bfd16822f402d6e"
    $a1="beacd481df0fdd80e82571ff2e3b2ca8614295670cc809e052fdf0c4d0d301608b37578ce9b92e74c3f0c62833348a47c453be4a771aee860bfd16822f402d6e"
condition:
    ($a0 and $a1)
}