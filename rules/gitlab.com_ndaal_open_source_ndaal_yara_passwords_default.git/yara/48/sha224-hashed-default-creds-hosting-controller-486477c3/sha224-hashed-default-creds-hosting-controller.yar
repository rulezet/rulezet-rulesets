rule sha224_hashed_default_creds_hosting_controller
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for hosting_controller."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a7b9da03f8ca12bcb6129a94229e247dc9b45ffc2ad8553514890cc9"
    $a1="62d28bd2046b7858bc01ea09f58aaaff3ca26b8267d7ee6146178a03"
condition:
    ($a0 and $a1)
}