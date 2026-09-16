rule sha384_hashed_default_creds_liebert
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for liebert."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="24d472ef95b6482dc059621f2e0f0526300195932f99146a05bc7d3a5b981e1407d3598593ed8f67dc6af5ee98328d0d"
    $a1="24d472ef95b6482dc059621f2e0f0526300195932f99146a05bc7d3a5b981e1407d3598593ed8f67dc6af5ee98328d0d"
condition:
    ($a0 and $a1)
}