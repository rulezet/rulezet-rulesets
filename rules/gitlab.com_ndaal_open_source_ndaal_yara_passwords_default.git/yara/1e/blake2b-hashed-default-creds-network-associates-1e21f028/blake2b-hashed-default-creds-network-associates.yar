rule blake2b_hashed_default_creds_network_associates
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for network_associates."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="faf5a7207d91c00e038e8488c21936552e6550f9fdccab3a1fdd6b0d57ca01d2fdce73f14c95e6c79fe69ac1ed6e4ab6c1d293be4f1222bfa1d19aa2e901f443"
    $a1="946ef07e9ab08014ece09632f9ac766ee6acc2a89df2339a7098c2d6578a5e9945ca094d7e1629fd736404c3e22995c63100f49f4826b27443fb000abac0f216"
    $a2="e119c1e54334cf65f157bb72f910fa9c13b373f2f1bb4617b78d310b93ebea97c2ff0fb6abf39d4490b94644529dd0156a322eab420ceda46a3515d117cbc902"
    $a3="d962358bd07f4410a4c23e17be89e07c8d8cf0797e53e27f2e4a72047bfe578ae6022fae203511f00e5db919451114a96ee64f304e1cb92c51e3fbaaa209017f"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}