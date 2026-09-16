rule sha384_hashed_default_creds_tridium
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tridium."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="19594d25947ecb7539be5f21a916b47e97b059b9fddc547cf9188be6ac809da480d66c4310e694e78ced79e95ac80c43"
    $a1="3d5ea073b8f423259a62eaf3f7d3dea51fbcb8073c90ddc9d9fb9910bad666d3e6c1b4ae19a683f2cb1e7085ab3b529a"
condition:
    ($a0 and $a1)
}