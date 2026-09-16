rule sha384_hashed_default_creds_ramp_networks
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ramp_networks."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="26444fe9e22e265a60f8ae1391c12a950221f2bfaad5a66afd93e3b24cc942993ded029bbd7375c9820fec9b461855c7"
    $a1="2af7729a74903f5d215037340f165366cdfe763e931e302985f27e8daf24bcbb4f77627cfdcd7d3980de34dd5ea2479c"
condition:
    ($a0 and $a1)
}