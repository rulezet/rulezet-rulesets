rule sha384_hashed_default_creds_rapid7_inc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for rapid7_inc."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="2a1b51ab81a1db19e434f7f684e0195dfeca98a2b87f2c95bb7d218c83a52c39620fa9c9f7facda7ab8435134e20267f"
    $a1="2a1b51ab81a1db19e434f7f684e0195dfeca98a2b87f2c95bb7d218c83a52c39620fa9c9f7facda7ab8435134e20267f"
condition:
    ($a0 and $a1)
}