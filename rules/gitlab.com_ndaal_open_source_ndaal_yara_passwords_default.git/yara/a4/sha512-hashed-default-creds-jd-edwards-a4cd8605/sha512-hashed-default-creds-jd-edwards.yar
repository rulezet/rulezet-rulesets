rule sha512_hashed_default_creds_jd_edwards
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for jd_edwards."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="05ef6e81d1805a3e2f045afb16463102ee6338ddc02b5c89cd5e029ffe7b38f0d20be158940ec035f8528e9783937729ec71958daa4a80604eccc77b1e76651a"
    $a1="05ef6e81d1805a3e2f045afb16463102ee6338ddc02b5c89cd5e029ffe7b38f0d20be158940ec035f8528e9783937729ec71958daa4a80604eccc77b1e76651a"
condition:
    ($a0 and $a1)
}