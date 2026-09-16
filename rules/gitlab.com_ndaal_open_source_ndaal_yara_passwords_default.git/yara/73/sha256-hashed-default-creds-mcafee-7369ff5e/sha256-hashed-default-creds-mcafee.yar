rule sha256_hashed_default_creds_mcafee
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mcafee."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0cdf5e87989e3cea40e51b5a8a3e22a6b7574424f74499a557eb02164464f86e"
    $a1="9d1ba59aea6eabbac8638a9227eb9445e7ecd11fbb5215d4aabab5c77e8c45c2"
    $a2="240be518fabd2724ddb6f04eeb1da5967448d7e831c08c8fa822809f74c720a9"
    $a3="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a4="8e21bc1543b4713b1de130b257708ea596a630feed6b381e8d8e127d9e9a795d"
    $a5="37ec336e7fd5d6b25e8b80dfe1ccc88cbc11826f38eeb881468227b25e02ae8e"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}