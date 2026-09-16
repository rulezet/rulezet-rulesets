rule sha384_hashed_default_creds_next
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for next."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9a11faa04445c9a632c733ff8787823b563dede908ef16e033e50e35a52861988729944c0560a01e90a0c89d688d77e0"
    $a1="7ed8c2c790aa83d6c3e404b5368f6832c18d46a0e98b9c7a7a5e3ef823e2c9f0e310abbf6f7ea9d9d883ccb64ec2736a"
    $a2="d3ea14b8ad2c447849fbcf27105f7b943093ca6be70cfa3726f62c9aa68ca6312a6f73c8284ec2904816028787f763e1"
    $a3="d3ea14b8ad2c447849fbcf27105f7b943093ca6be70cfa3726f62c9aa68ca6312a6f73c8284ec2904816028787f763e1"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}