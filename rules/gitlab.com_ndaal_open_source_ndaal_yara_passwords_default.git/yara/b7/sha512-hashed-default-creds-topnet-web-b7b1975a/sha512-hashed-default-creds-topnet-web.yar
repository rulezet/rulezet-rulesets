rule sha512_hashed_default_creds_topnet_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for topnet_web."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="67df429921ac339e71aeae3b5278b725fdf191f20b4e79f631549803faa05f557c112e5dfc61995e7ac20fe39687b02bb9105298b91fa8a82303f87fb50c4fe9"
    $a1="67df429921ac339e71aeae3b5278b725fdf191f20b4e79f631549803faa05f557c112e5dfc61995e7ac20fe39687b02bb9105298b91fa8a82303f87fb50c4fe9"
condition:
    ($a0 and $a1)
}