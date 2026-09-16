rule sha512_hashed_default_creds_remedy
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for remedy."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1dfe7eee12f7ce4464aaf82ce5ebc0cce393942642a85dd40af57178479fe39674c06d4ca5bdfc9970396b5c12aa54c088095c7cdf2a8b7bb4b3f0e7e3b01425"
    $a1="f40435d34eddfbe0f417b8cf3b221ccc6a8cbd95dc46240bc1d6d8d7812efd3448184ce605ebeb621715307f51a017497cb33807306ad340e74d6dc910235f4f"
condition:
    ($a0 and $a1)
}