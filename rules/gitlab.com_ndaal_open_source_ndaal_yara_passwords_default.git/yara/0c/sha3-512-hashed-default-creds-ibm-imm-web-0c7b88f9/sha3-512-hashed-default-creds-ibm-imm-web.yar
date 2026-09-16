rule sha3_512_hashed_default_creds_ibm_imm_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ibm_imm_web."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="efc03c23d9d9169696dd61e13190c9afa71026fdfa0b2dad03db08caad052e38212baec007daa497aec6f35b0834fcb7cf856524743a1ca35ac59fa8787ab464"
    $a1="3e73b2c6a80a10e2c19d5d5333bd5ad2e26df2ad9ab4047595dd3922d8bb26ae6d41fd7e648e7a28ac3b0ccc643b034a911608da2a362385a8608240601abd52"
condition:
    ($a0 and $a1)
}