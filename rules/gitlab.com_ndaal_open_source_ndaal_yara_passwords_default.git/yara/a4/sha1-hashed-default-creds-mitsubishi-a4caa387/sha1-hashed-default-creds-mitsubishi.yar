rule sha1_hashed_default_creds_mitsubishi
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mitsubishi."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="2adb789a3e5ec535532691f7a65cd8e957394f30"
    $a1="2adb789a3e5ec535532691f7a65cd8e957394f30"
    $a2="fc0b20c1ec8e14973c1f4c9358530bd6d25777a3"
    $a3="fc0b20c1ec8e14973c1f4c9358530bd6d25777a3"
    $a4="c72877c51a77b2aafc0771d821a262a5c6a6186a"
    $a5="b4c54dbe2c34e9c1cbf27de79a3661717b1fea52"
    $a6="12dea96fec20593566ab75692c9949596833adc9"
    $a7="35675e68f4b5af7b995d9205ad0fc43842f16450"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}