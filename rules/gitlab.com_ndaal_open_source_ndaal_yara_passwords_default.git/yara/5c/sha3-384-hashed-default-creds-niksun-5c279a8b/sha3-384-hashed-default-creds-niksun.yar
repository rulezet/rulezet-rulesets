rule sha3_384_hashed_default_creds_niksun
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for niksun."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="830bb9a985c04eccadbc32f9cbad61698a0c31ac1a92ae40e701066e919a7369ecd02c48afeb0dc7364f69742069e017"
    $a1="36b46464be360e9c12478de60a363b93217ee2ff7abe18bdef2d51fce22b72874a13dc518b300a5addab42a4e755deca"
condition:
    ($a0 and $a1)
}