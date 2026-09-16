rule blake2b_hashed_default_creds_niksun
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for niksun."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="eca7eb4aca59d1a50ae994605c2a77e972cb44f566c4be2c15e866ade60e6505587ba24cea30fc27971ff09a53e54bdd27bb2f63a52ebb72d4302f50b46b0abe"
    $a1="14ef26a80b45f8113198d534133f6bd1b720eb249ec0a195b87e82c84495e76517faca41a0cd7a7c94b7053926fc505a422b886395447f77ae2512c98d148dbb"
condition:
    ($a0 and $a1)
}