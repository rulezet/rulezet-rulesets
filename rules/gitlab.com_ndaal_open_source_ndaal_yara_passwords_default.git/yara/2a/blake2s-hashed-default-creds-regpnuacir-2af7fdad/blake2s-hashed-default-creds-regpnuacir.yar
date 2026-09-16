rule blake2s_hashed_default_creds_regpnuacir
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for regpnuacir."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="de613f8c4e16e20707b811049659a3bfb6de9a154885c4e63bc4cbdebc387bda"
    $a1="cf5d9105309f036fd3449ef4fe73905e6833a5f5ed6e84517da6b211404a12c7"
condition:
    ($a0 and $a1)
}