rule sha1_hashed_default_creds_exacq_technologies
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for exacq_technologies."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ca6656065446c384cc3e49d89f234d477db2a35c"
    $a1="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a2="70952c81372205250e0e9e8ba8c5e1f022ea104b"
    $a3="12dea96fec20593566ab75692c9949596833adc9"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}