rule sha512_hashed_default_creds_metasploit_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for metasploit_ssh."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1250811abed3d38fc35ae12c133d837bb3bf2df78b8941dfd0fc64c003899573dc3e44e4308ad1d80c6afd1af562b47a0d91f1fc515a7feb6b49ccf476f1d6b2"
    $a1="1250811abed3d38fc35ae12c133d837bb3bf2df78b8941dfd0fc64c003899573dc3e44e4308ad1d80c6afd1af562b47a0d91f1fc515a7feb6b49ccf476f1d6b2"
    $a2="7afcf71d8fb958b8140b7a5e0eef3aa44ebdab94a11180d7bf5ad63489bd4dfa1972af70875890aa01fe63fb0063be8aa6ed9853bfdc65e435853929b0993cb0"
    $a3="7afcf71d8fb958b8140b7a5e0eef3aa44ebdab94a11180d7bf5ad63489bd4dfa1972af70875890aa01fe63fb0063be8aa6ed9853bfdc65e435853929b0993cb0"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}