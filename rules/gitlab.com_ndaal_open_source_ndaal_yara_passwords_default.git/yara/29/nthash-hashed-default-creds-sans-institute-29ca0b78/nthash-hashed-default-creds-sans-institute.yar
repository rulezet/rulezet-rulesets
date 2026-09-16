rule nthash_hashed_default_creds_sans_institute
{
    meta:
        id = "2PcdCwxWP70KLJblglgwrz"
        fingerprint = "2d0d9f52496465df39d12b165fa212bf1f5f782f65722213e3b5accea4ff4295"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sans_institute."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5f9469a1db6c8f0dfd98af5c0768e0cd"
    $a1="a6ca6374172933fc9f172ed6df116e1b"
condition:
    ($a0 and $a1)
}