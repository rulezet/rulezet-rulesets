rule sha1_hashed_default_creds_ibm_storwize_v7000_unified_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ibm_storwize_v7000_unified_ssh."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="255007fe25f0a05cb9ae4e49cb63afe40743c341"
    $a1="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a2="ebfc7910077770c8340f63cd2dca2ac1f120444f"
    $a3="dc76e9f0c0006e8f919e0c515c66dbba3982f785"
    $a4="7c6a61c68ef8b9b6b061b28c348bc1ed7921cb53"
    $a5="8e67bb26b358e2ed20fe552ed6fb832f397a507d"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}