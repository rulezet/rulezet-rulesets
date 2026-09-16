rule sha384_hashed_default_creds_pollsafe
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for pollsafe."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="50aa1cd8d34b822285163a3c43124ba44a2ef47c10ce090fb42dc1aa556d861e75ddf343a13f0b630b6de4e78dc8ea07"
    $a1="00a996752c972e54a87c53b4427c0d714ed6dab7d232d9c62a679dfe92bbe69a3e3eaf593e1a78813da750aafba2a61b"
condition:
    ($a0 and $a1)
}