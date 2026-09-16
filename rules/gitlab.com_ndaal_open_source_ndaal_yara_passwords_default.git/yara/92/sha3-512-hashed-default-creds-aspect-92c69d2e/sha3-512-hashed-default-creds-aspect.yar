rule sha3_512_hashed_default_creds_aspect
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for aspect."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f318fcacb18e3f9830c1e965eb4ce3066d7aa4a86620bdeca6bcd53bea99c6676645d9e4aaf860cef4d7abbcc1c07d982091fbf6c5b5835e8a308bbf589e452a"
    $a1="d4ddffe7e3cbeb7e980e98e15537dc5913aed29df5c2aee851671e29060eea07856526665092097db9e1db12cb0c7a3680d7f48ea1eb51eb11a039add5259cb4"
condition:
    ($a0 and $a1)
}