rule sha3_512_hashed_default_creds_lindsay_electronics
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for lindsay_electronics."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="004ba88134928516ab50855f74119f9993de454a9c4d677fe4f7c83bce4e821e06fbcffb46bc5a0c8a681b979debad81f12ca6ed21b25ba216ab48ec76896d8a"
    $a1="03f70d78376b41fe748f5414954cf4cad830dd6ad583c2994b5ebb1bc12d2e028827fce6396bc4f6ab0d584f725748b30629468d87fe4bdd2a37bdf726300066"
    $a2="004ba88134928516ab50855f74119f9993de454a9c4d677fe4f7c83bce4e821e06fbcffb46bc5a0c8a681b979debad81f12ca6ed21b25ba216ab48ec76896d8a"
    $a3="004ba88134928516ab50855f74119f9993de454a9c4d677fe4f7c83bce4e821e06fbcffb46bc5a0c8a681b979debad81f12ca6ed21b25ba216ab48ec76896d8a"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}