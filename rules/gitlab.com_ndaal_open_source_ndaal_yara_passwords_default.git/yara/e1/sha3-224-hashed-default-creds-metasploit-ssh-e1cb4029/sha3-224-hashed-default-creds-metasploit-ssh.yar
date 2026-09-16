rule sha3_224_hashed_default_creds_metasploit_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for metasploit_ssh."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="470ece5bbfc1cb409a4899c3d9c2bbf16342a5331cff819e2d143fc4"
    $a1="470ece5bbfc1cb409a4899c3d9c2bbf16342a5331cff819e2d143fc4"
    $a2="5a1f82cb4122c4e4412620f0873b4dad93ec30732c0e3a135287dc71"
    $a3="5a1f82cb4122c4e4412620f0873b4dad93ec30732c0e3a135287dc71"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}