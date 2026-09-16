rule sha512_hashed_default_creds_xd
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for xd."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6d16e989de5314f3eff5e0c4a24c2bf0fd7f8fe395e713ac839b325a10c4ed1191d1c972c49471efcaa197275b652464fc19007ea5f3542b798c6295b38a2b31"
    $a1="6d16e989de5314f3eff5e0c4a24c2bf0fd7f8fe395e713ac839b325a10c4ed1191d1c972c49471efcaa197275b652464fc19007ea5f3542b798c6295b38a2b31"
condition:
    ($a0 and $a1)
}