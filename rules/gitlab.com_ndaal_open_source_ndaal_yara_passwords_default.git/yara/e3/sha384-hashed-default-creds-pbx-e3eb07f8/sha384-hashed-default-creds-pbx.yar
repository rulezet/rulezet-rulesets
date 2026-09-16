rule sha384_hashed_default_creds_pbx
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for pbx."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d9007f3215dc7e388200e1a5c8c59f2481a7ff99735090964ac2c9ecd3a25dc2f54bc41079aff431ff09328ea4837b18"
    $a1="d7d4375a6045ae4b2dd32d6ccf53ee632c2d858cc5e67b2292f60e7e497f3f22efa1093e67ff66301ef64633437df096"
condition:
    ($a0 and $a1)
}