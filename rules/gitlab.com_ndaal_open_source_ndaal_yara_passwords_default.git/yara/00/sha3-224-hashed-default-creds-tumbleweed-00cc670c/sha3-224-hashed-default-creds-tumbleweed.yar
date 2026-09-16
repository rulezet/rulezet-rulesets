rule sha3_224_hashed_default_creds_tumbleweed
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tumbleweed."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="68c20bc7da2d62c28328c9ae082f22a195c764c407a7c68533ce2837"
    $a1="24934871b4dd5d625da5ec9346416245e6e3789dd6d7e48bb870db3e"
condition:
    ($a0 and $a1)
}