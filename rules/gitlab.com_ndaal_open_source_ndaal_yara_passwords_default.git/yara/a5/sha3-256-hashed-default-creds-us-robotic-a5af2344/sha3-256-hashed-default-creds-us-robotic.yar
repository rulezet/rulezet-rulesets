rule sha3_256_hashed_default_creds_us_robotic
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for us_robotic."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0c1e7a6a950cea0c33421085aa5ff978493162c6693e3e6caa2c73cf1e08c0d3"
    $a1="0c1e7a6a950cea0c33421085aa5ff978493162c6693e3e6caa2c73cf1e08c0d3"
condition:
    ($a0 and $a1)
}