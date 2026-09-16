rule sha3_384_hashed_default_creds_tridium
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tridium."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="86e44d51fca52759c877d17f7d10d5680c75425b318960d3f052842a896fa676143b7ff82ccc006900d0a0070caab41b"
    $a1="d2b376342f8861c78ac61a7d2b22a517e60ff6ca82c577e2a6748ce51cf57fe67617d028f2853526d53a6a3e3b982db0"
condition:
    ($a0 and $a1)
}