rule sha384_hashed_default_creds_canonical_ltd
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for canonical_ltd."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ea69601ac8556ed25d1842fb6dc2139f6fdca5592d5645abb2511549363abbd02df2ff6409748e8c8ae14640af518b76"
    $a1="ea69601ac8556ed25d1842fb6dc2139f6fdca5592d5645abb2511549363abbd02df2ff6409748e8c8ae14640af518b76"
condition:
    ($a0 and $a1)
}