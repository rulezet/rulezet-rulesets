rule sha3_384_hashed_default_creds_server_technology
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for server_technology."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="53501ed3076ef6f153e84a7af330bba544732c69b99a54743440286eaee9ff920fb16bb5b4d4b5c7dbd67d4b59ed700b"
    $a1="6c54710022a8933dd9011a65ceccde2c7c63e0423522593e656de682ae8a7a4c505f1740d00c8f168870d03fd12d0108"
    $a2="7d6e486b6697ca11c2b07df0039a8be7fc6b411826cab0ea9133b2a312c5fa77ccc3cabd211dbbd2238f327e13d18314"
    $a3="73094024fc0a8316b8e48af182bd808689baa8bf8b144ee444a065899c5acf3591211c2aa58aefbc1950c27d8152049a"
    $a4="d8584408ad7697ab33140915acec59af1d806a8cbaefc7ac406d113b0b30a8af2b30324205902f7e03d999ef8480dcd9"
    $a5="1489ff227027eb2f8262d3e5e87f276e940cbe3849885ee59e6ab5b78a517617ef491e1f532671ec6ae18a4b7e3c17cb"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}