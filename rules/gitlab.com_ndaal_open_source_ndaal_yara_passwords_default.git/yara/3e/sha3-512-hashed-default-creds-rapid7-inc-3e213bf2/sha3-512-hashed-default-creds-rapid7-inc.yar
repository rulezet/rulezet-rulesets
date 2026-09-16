rule sha3_512_hashed_default_creds_rapid7_inc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for rapid7_inc."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="47aa44fbbfc7163b0b68eb6312d403a25c78c97bef1ab050d0fdab858b7ee32efcb98d4f88a9f4f543128b4634d460fa10b207411c9c5dcc971b38efec224bed"
    $a1="47aa44fbbfc7163b0b68eb6312d403a25c78c97bef1ab050d0fdab858b7ee32efcb98d4f88a9f4f543128b4634d460fa10b207411c9c5dcc971b38efec224bed"
condition:
    ($a0 and $a1)
}