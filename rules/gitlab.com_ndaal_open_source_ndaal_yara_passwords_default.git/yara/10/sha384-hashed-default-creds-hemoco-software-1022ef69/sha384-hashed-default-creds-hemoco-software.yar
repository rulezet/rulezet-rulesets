rule sha384_hashed_default_creds_hemoco_software
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for hemoco_software."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="fd0667519792aa42268834c586fc30d292cc5fab088ac3ae4812e08698d74745dfb3996c53d30e4214fcbc5bc2678888"
    $a1="77c8662a4cd2fad81e5acbfb7365c6f9aae1e3810d067d112436754841517415d39aaa4bc1b02e573783b0d38767d853"
condition:
    ($a0 and $a1)
}