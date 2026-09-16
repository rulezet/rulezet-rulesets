rule blake2b_hashed_default_creds_tellabs
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tellabs."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="84a754518520b30aa5bc6d084dc27ed6f9ab11ae414cae081d88bf0bbe5e60f8e5f2ee9b56f9b99cc52ff2d62533001d74f101dc3bb3b64973bf36701be1e952"
    $a1="da23f3a4e096b0816ec2070050eac6cd9243240dad0b5cde6573e41d6852939ac5468aa9d81b5fbe156feb231a069f5afe8a5146630abc7807b1e0dcdaeb049a"
    $a2="642e7c08a1ad6fdbfb1ef8fdadec06861eff496ce58bf46b0fd486451e8bf1452834c3e2514a0c033426ebffe426d5076a9663cde30892ad6e2f70620ecd93a1"
    $a3="8cc5ef0e16c1d5a69f0f7d7a54234e59b465c589a57e98ae993f305934f550eec092ab6023e7e162040ed7342ce054f9d1f8a93f174b1d3153adda60fe8ae819"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}