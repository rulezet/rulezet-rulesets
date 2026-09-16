rule sha512_hashed_default_creds_glftpd
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for glftpd."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6852e9af659a13636332123e10540146cd698da28872236d08ce49c17cef98d2e45e58c3c8cacf2767215b0753c23f85186e1f90149894a2579471c8a948648f"
    $a1="6852e9af659a13636332123e10540146cd698da28872236d08ce49c17cef98d2e45e58c3c8cacf2767215b0753c23f85186e1f90149894a2579471c8a948648f"
condition:
    ($a0 and $a1)
}