rule blake2s_hashed_default_creds_system_32
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for system_32."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="66e754709229a1a76f12b770d612d4dba1d51e28894e2dce1b53ca15104f84c0"
    $a1="83429da7b305984c64cbf2dc563d752d4a79717f286e679afc9b2daea14ef86b"
condition:
    ($a0 and $a1)
}