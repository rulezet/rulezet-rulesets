rule sha384_hashed_default_creds_webramp
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for webramp."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="fcf65db8bc5ba9a7cd5cbfc188eab9d30bfd514f753dead12a76cc42cb8f4546b2f483b117b2d578ed20ac381db8b5de"
    $a1="2af7729a74903f5d215037340f165366cdfe763e931e302985f27e8daf24bcbb4f77627cfdcd7d3980de34dd5ea2479c"
    $a2="26444fe9e22e265a60f8ae1391c12a950221f2bfaad5a66afd93e3b24cc942993ded029bbd7375c9820fec9b461855c7"
    $a3="2af7729a74903f5d215037340f165366cdfe763e931e302985f27e8daf24bcbb4f77627cfdcd7d3980de34dd5ea2479c"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}