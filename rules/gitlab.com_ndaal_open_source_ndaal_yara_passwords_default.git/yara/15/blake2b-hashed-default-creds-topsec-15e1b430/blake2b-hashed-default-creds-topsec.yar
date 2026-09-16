rule blake2b_hashed_default_creds_topsec
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for topsec."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="73efc681de8ba9dc54a5f8c9f3ab5ff18fd4b01f21ffadd4a3e4ac616f76dceedd4847e87c89210bfde23382dbb16bafc6605f0dc7c02c8ee97e3ecd41027f6d"
    $a1="8eaad423dd736e736ed555d895ab8973bd6af729b4d5181cd96cf4c866e8455767fa11dd6a2632090c61f3df15f048b459e8e4e9af7c2436e13bb4fd2ad31f7d"
condition:
    ($a0 and $a1)
}