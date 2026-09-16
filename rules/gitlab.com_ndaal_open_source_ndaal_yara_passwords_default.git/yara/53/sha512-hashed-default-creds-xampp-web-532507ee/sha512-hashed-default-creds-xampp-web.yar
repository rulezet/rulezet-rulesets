rule sha512_hashed_default_creds_xampp_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for xampp_web."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="739d862fc58236987199ea91e7c0d615444d4a84db7b76885dd58232ec8aae29b44cf79a0c17941cd729f967a92324f9ba3d388c651608dff19c5793aa5ce247"
    $a1="b42fa1ce2b65fd6f4a8501b64deef38fa3e87059c6f015eb5848c50aaa538dc812c8d36dba61f4c505d54516707a3997d555ff08dd447617d9cd3180df95204c"
condition:
    ($a0 and $a1)
}