rule sha256_hashed_default_creds_norstar
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for norstar."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9981b28abf766d92c3761fe28a1e3f7732310b45e75f5b349b5082e8c78f0676"
    $a1="c6707bdeb5297764f5f202a754c931e6f4dc5808a61278e34b132f9f145ee996"
    $a2="b7e20440296364fac9a66a07540b1c3acb2a913b6e903c5387a8bd233535a765"
    $a3="f9ccc825e2c582ec62a6b3b62931579d652c5d338179d77af50a327e28e797e5"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}