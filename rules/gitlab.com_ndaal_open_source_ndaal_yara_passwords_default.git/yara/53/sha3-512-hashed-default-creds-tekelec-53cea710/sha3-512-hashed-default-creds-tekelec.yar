rule sha3_512_hashed_default_creds_tekelec
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tekelec."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="eae654e894a01929842ad4de51f57855b2b0567dbea71b75e622c76d03addea718bedaeff3aedca98bfd56de5644a4915158f1c106af7cc34e9f883ac083a1f8"
    $a1="eae654e894a01929842ad4de51f57855b2b0567dbea71b75e622c76d03addea718bedaeff3aedca98bfd56de5644a4915158f1c106af7cc34e9f883ac083a1f8"
condition:
    ($a0 and $a1)
}