rule sha3_384_hashed_default_creds_att_arris_nvg589__nvg599_sharknatto_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for att_arris_nvg589__nvg599_sharknatto_ssh."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4ae97fc8e8449c825cceffee898ca8b9309ed586f80cd1352616da87e2bb521934fae10e8b77278ee57b2977b915f370"
    $a1="090a6fb8c4f645041204999bc707a6fe07fc75e7dc71cdeed4aaa45d78abcd22b4efb74bb31b1bb0a1645ea3cbb946f0"
condition:
    ($a0 and $a1)
}