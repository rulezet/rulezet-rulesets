rule sha224_hashed_default_creds_metasploit_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for metasploit_ssh."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8a7d3495f816beda79e2d039d3edf9a5d1fc1f639cd76519f933e0d1"
    $a1="8a7d3495f816beda79e2d039d3edf9a5d1fc1f639cd76519f933e0d1"
    $a2="78192940297071d6c4550252a25fb405928fce831b80c9740c01cfa9"
    $a3="78192940297071d6c4550252a25fb405928fce831b80c9740c01cfa9"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}