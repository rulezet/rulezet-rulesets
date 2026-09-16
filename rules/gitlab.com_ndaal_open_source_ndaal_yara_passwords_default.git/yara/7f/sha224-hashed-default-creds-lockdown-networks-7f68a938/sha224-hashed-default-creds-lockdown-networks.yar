rule sha224_hashed_default_creds_lockdown_networks
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for lockdown_networks."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9ecc08a585aa7038c129f8036120f4ec63c757426c7b642fd0849dcb"
    $a1="4d8f45908245b2a55cc49ddd019c70e37b4c49f2e7e948539b942ffe"
condition:
    ($a0 and $a1)
}