rule sha3_512_hashed_default_creds_avaya_contact_center_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for avaya_contact_center_web."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="468975f36294ef9d7d1d7b6e988c8e9f1e2a791728bfcbc7b0c505028fc7b5610c68042df6b7b53517d10390cdaedff7bcd8654edd432e73e47c4f66939c0a26"
    $a1="468975f36294ef9d7d1d7b6e988c8e9f1e2a791728bfcbc7b0c505028fc7b5610c68042df6b7b53517d10390cdaedff7bcd8654edd432e73e47c4f66939c0a26"
condition:
    ($a0 and $a1)
}