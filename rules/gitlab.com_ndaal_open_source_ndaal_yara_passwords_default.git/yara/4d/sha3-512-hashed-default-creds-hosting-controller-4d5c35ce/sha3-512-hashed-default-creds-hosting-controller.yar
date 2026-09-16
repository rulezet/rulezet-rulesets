rule sha3_512_hashed_default_creds_hosting_controller
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for hosting_controller."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0344e65c48c200f3196aa2bbaae313b56b8ed87b1e7de68b08278b82ab5e4ce2e8a8bcfd1f34ffa8255334ef812a5e578ff04a930c9f82af5b6618409724bd02"
    $a1="a24743085ac5bf0875dcf01ad9b6852d98eb41174d490b2ecea4e8e32aa9230e4c9d9ff44440d598b3dfa043c416c0d2c5462c11cb2c39420e9b1c11afd8fc18"
condition:
    ($a0 and $a1)
}