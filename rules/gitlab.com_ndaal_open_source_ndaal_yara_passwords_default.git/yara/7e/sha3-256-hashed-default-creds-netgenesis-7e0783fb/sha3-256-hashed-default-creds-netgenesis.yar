rule sha3_256_hashed_default_creds_netgenesis
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for netgenesis."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="2a9afaab1fea11cae88ee931e7355253cb3fd60e0eecf1dcd31bf6bcf91bc361"
    $a1="2a9afaab1fea11cae88ee931e7355253cb3fd60e0eecf1dcd31bf6bcf91bc361"
condition:
    ($a0 and $a1)
}