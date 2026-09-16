rule sha3_512_hashed_default_creds_inova
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for inova."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e58ad8d988825bd0074970c8248f7b9fc54ea44f7d6256ff50e41fd3aa5ac007eed9c1e8040d527f6bbee242b377e1d533406f1bd73c15c5799c8c8e4d3756ff"
    $a1="f4c61490c7b5a2c42d0774585174dce370c4f0139bcb0169d91a55980eb19dafe9dfea349440e5ec2b28f7793b141c95d36f9ec99171517b13e30f284144f11e"
condition:
    ($a0 and $a1)
}