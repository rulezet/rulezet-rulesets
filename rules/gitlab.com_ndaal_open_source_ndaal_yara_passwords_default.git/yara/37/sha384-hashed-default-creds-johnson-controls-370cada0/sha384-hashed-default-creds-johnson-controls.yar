rule sha384_hashed_default_creds_johnson_controls
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for johnson_controls."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5f6a2daec364126c664ea8906ad8845e94dacfd4e19debb92c38827b90819bb85e221221af7f7686e99e368a1885f32b"
    $a1="52eef3bb62146d67d3d739b1d86ac74562320aecbddc38184592bdf24a61bf116e838495b0c73ff9aa57f5f9e4c3166d"
condition:
    ($a0 and $a1)
}