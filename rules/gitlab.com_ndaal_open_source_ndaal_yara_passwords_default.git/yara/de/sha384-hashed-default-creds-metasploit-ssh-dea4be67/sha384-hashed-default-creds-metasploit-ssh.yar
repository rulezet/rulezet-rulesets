rule sha384_hashed_default_creds_metasploit_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for metasploit_ssh."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b9f6bcd3e7a2ebaa4dae2d3c768f5a3e2e69cca6e3e0dc48b9a40836810e97d866d4d99a22b630a58a7a8c4f12e416db"
    $a1="b9f6bcd3e7a2ebaa4dae2d3c768f5a3e2e69cca6e3e0dc48b9a40836810e97d866d4d99a22b630a58a7a8c4f12e416db"
    $a2="6a12c808653fd857c5076fd49bff500e03486d78eab8872c26c563d7f8ff12a200d7cd8f5453376100dc089f3e54ba16"
    $a3="6a12c808653fd857c5076fd49bff500e03486d78eab8872c26c563d7f8ff12a200d7cd8f5453376100dc089f3e54ba16"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}