rule sha3_384_hashed_default_creds_interbase
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for interbase."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3b0be128d62f2800d7c12e8c90d361257b3df6638ab81a873d6c095a6357922cb910e3fb506739c6b812a564b49810da"
    $a1="5f14ad767216390bbea72abcc67d8bbb0005715e5993bc3ad6a15eef8fd93689fa551a434ee899fdc08ac3b6f7850083"
condition:
    ($a0 and $a1)
}