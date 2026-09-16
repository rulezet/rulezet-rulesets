rule sha3_384_hashed_default_creds_ca_process_automation
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ca_process_automation."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d55779c15b5623e93f0d37c57f90073b2ee7610531d0a3f56a02909e5297cf2928af2030a78c40ac74cd6329869fc476"
    $a1="d55779c15b5623e93f0d37c57f90073b2ee7610531d0a3f56a02909e5297cf2928af2030a78c40ac74cd6329869fc476"
condition:
    ($a0 and $a1)
}