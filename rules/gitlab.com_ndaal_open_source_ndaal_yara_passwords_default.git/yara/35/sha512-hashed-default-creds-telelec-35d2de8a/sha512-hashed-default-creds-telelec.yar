rule sha512_hashed_default_creds_telelec
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for telelec."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a8783749cff88f94fe983f9e4123a3b5848216eb0fa95f0c334abe27fea06c391e376512641c88c0ded61c2b08446a29c38f90a38583b9eb90a42d218ce24c39"
    $a1="a8783749cff88f94fe983f9e4123a3b5848216eb0fa95f0c334abe27fea06c391e376512641c88c0ded61c2b08446a29c38f90a38583b9eb90a42d218ce24c39"
condition:
    ($a0 and $a1)
}