rule sha3_384_hashed_default_creds_hyperic_inc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for hyperic_inc."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c758d9d252b8f071b1088d3f59ff670741ea735b2beede4860eb95c4a42cb49cb020c1ec2190723ed70a57af803be906"
    $a1="c758d9d252b8f071b1088d3f59ff670741ea735b2beede4860eb95c4a42cb49cb020c1ec2190723ed70a57af803be906"
condition:
    ($a0 and $a1)
}