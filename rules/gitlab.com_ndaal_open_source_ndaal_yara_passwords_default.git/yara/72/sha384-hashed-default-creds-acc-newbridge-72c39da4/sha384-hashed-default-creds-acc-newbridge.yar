rule sha384_hashed_default_creds_acc_newbridge
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for acc_newbridge."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f89feea53b3d49c93be9bba04242fa183701f8dc45a96978254f1afead273efeb73c2acab0fdac339c281731894b2221"
    $a1="f89feea53b3d49c93be9bba04242fa183701f8dc45a96978254f1afead273efeb73c2acab0fdac339c281731894b2221"
condition:
    ($a0 and $a1)
}