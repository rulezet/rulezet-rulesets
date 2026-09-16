rule sha512_hashed_default_creds_ssa
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ssa."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="211b0236d991cc0a1eaa6f76fbb5f16fb3a828e943420ce003ecfca4309028697fcb47f55617bdd26b630a9b066d994f25854515ffa399ceb83a3cbeede4f8ce"
    $a1="211b0236d991cc0a1eaa6f76fbb5f16fb3a828e943420ce003ecfca4309028697fcb47f55617bdd26b630a9b066d994f25854515ffa399ceb83a3cbeede4f8ce"
condition:
    ($a0 and $a1)
}