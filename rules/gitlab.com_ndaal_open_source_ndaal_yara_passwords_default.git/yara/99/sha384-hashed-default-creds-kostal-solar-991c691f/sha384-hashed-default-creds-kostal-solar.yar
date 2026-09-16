rule sha384_hashed_default_creds_kostal_solar
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for kostal_solar."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="44063617e292c8cb2acaaf23ec2445cc97296504f822d7be1676289ded251e7a4b6f89d23995e9234e746b3804c95a34"
    $a1="2668e40017e0d4ce0a7e0ee0f5641f776431b05888d35f78a8583cc8be2c47c37f2488141bdbd5ad02550f718bc89041"
condition:
    ($a0 and $a1)
}