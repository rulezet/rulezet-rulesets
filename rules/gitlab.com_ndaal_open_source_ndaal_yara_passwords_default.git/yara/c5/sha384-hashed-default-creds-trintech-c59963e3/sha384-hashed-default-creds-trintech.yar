rule sha384_hashed_default_creds_trintech
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for trintech."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="62fb33c82319c9b810ec04e6f857100d715960c743fb880838e86ea7d8f2dc41198278140f45e98e3e55ada662d31e2b"
    $a1="a48da4451de79b6cc9c0e48395e9d8625183a011e4248f1379f43205a5ae9a0629757fb1fb3cf4f47952f462ee870efe"
condition:
    ($a0 and $a1)
}