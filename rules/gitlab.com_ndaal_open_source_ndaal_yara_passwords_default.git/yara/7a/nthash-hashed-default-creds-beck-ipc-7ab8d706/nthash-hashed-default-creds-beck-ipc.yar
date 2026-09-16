rule nthash_hashed_default_creds_beck_ipc
{
    meta:
        id = "6MFr373GTdpp1YdKKLOuva"
        fingerprint = "2febd9b45f326855f97257fd0cbbad44a377c86e48e4a8cb1eba0554b767d3e8"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for beck_ipc."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e019d1cb1c34a638cc71046914e3785d"
    $a1="e019d1cb1c34a638cc71046914e3785d"
condition:
    ($a0 and $a1)
}