rule blake2b_hashed_default_creds_powerchute
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for powerchute."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="bc7c95e44b78c6f022d0a94d6c7c07057eb3981f6cccb69a67a2fb314c29525c5923cfe941018d3cf2ebc1676d947bb96092e8293e2d42a4d66dd7893fe181f7"
    $a1="bc7c95e44b78c6f022d0a94d6c7c07057eb3981f6cccb69a67a2fb314c29525c5923cfe941018d3cf2ebc1676d947bb96092e8293e2d42a4d66dd7893fe181f7"
condition:
    ($a0 and $a1)
}