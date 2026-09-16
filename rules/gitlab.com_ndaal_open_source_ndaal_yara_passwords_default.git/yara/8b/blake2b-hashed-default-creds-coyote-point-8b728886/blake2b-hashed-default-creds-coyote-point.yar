rule blake2b_hashed_default_creds_coyote_point
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for coyote_point."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="986dea7b25676a9f428dfb2ad7b34159afca8f57ffe66574e030d36157b4386157eb98cf0314d69b34d3a90a0a13fe770d3f3eb0e990d62712540fd9521218a4"
    $a1="02d3f65c4651ded83a3aabe0c50bcaaa2b4cd04c092bc4bf939f77add5ef0c6a2a93d53aa2d04e63d1242113e91a25abdbfcb6f515c21374b6383560a9be6e60"
condition:
    ($a0 and $a1)
}