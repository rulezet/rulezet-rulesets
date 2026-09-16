rule sha3_384_hashed_default_creds_metasploit_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for metasploit_ssh."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="117909d07776024d5bcc2c958d4e5d4f6de2425de9366f29e0d8819988b0ce1b1c5a7e7834ad1ec06d1cf515e3f8bf41"
    $a1="117909d07776024d5bcc2c958d4e5d4f6de2425de9366f29e0d8819988b0ce1b1c5a7e7834ad1ec06d1cf515e3f8bf41"
    $a2="1a57512c9cb0b1e7030c6d087f984997d0ae178d63170e2a9f1129e66feb2a202c09a1791bc0aa18f38898cd14da3c87"
    $a3="1a57512c9cb0b1e7030c6d087f984997d0ae178d63170e2a9f1129e66feb2a202c09a1791bc0aa18f38898cd14da3c87"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}