rule sha1_hashed_default_creds_webramp
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for webramp."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e9ff995a4b5fefd80282effd1f6b52d3dd20a9f6"
    $a1="940787ecca1e4710059774a6bbdcd08fb66b1029"
    $a2="3758b1488cd03d54e9b6ec7f337c85635f36d4cd"
    $a3="940787ecca1e4710059774a6bbdcd08fb66b1029"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}