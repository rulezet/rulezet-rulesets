rule sha512_hashed_default_creds_episd
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for episd."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="be843b8d5b590eb0ed4351404aed9187a24acff292fc299bc2a8c5e4c2f42596de7d90b105621cde3d48b5e0431724bd2df4fb36f5d0dc112e297da46104d073"
    $a1="922d076069b1df893fc010b7a6d2aa55c7c4c5d194f163394a4c864de5754131c17bfa94ac1667f56b5181cc7eca5dc3a09444caee6eecf16114926bb29f7e79"
condition:
    ($a0 and $a1)
}