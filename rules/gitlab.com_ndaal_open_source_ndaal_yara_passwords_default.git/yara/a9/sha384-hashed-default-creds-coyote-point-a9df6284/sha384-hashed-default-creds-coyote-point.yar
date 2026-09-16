rule sha384_hashed_default_creds_coyote_point
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for coyote_point."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="afa27ea8161475649d5273a7929f1d3477933c2e028da1c97156c5395cef2def92506565edb7bf8fd61572a2b68318f6"
    $a1="a9d41a93843c5be214435e7e9b5bb68cb1008abd1349fe7aa67e0a5542909a16692833b741851efd00e0345c751a73f5"
condition:
    ($a0 and $a1)
}