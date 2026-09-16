rule sha512_hashed_default_creds_155
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for 155."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3edb18ab9cdd4b29aa5f73c8591ea2ee40b182769e4d153577369f3720a38960cb9d4caef3a70bf6cec3c63b74a506fcc6ed2cccc185001f6911e6d9ca4a8539"
    $a1="225d05b918519458a8fcc1e6493a4e854c004da76f6250b8f52197f47094f71ee984725c31446a1967f0d55f4dc74793dd44d932f2bdf50d77d4288d663bf1ab"
    $a2="03e27e1cb5c4dc29a516e09233b4ab6d6521eb98d2da9be0522e197798149f9be841dafc8833c431f295d6ce1d1fe6beadaaa1d31d726d227f0627c82757664b"
    $a3="03e27e1cb5c4dc29a516e09233b4ab6d6521eb98d2da9be0522e197798149f9be841dafc8833c431f295d6ce1d1fe6beadaaa1d31d726d227f0627c82757664b"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}