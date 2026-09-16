rule blake2b_hashed_default_creds_cyberpower
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for cyberpower."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3a96a3e4b483eab19b1755a957f541eabec97a36931d7a6a33c872b4ca7bf18db9faee4a48f956df81a3635b2f519ee0c6860cf2eab9f0127fe2f24c43233c0f"
    $a1="3a96a3e4b483eab19b1755a957f541eabec97a36931d7a6a33c872b4ca7bf18db9faee4a48f956df81a3635b2f519ee0c6860cf2eab9f0127fe2f24c43233c0f"
    $a2="3a96a3e4b483eab19b1755a957f541eabec97a36931d7a6a33c872b4ca7bf18db9faee4a48f956df81a3635b2f519ee0c6860cf2eab9f0127fe2f24c43233c0f"
    $a3="2efa3755160d85e0ddc6a827f9a458a19829a83d286f0b6a46960491558320e74a3dc092986ead0b95e0ade7e368e363056a1396fdba590669fc1e631edf11ea"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}