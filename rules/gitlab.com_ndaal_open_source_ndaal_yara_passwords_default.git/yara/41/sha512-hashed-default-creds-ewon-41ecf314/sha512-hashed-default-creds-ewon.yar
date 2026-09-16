rule sha512_hashed_default_creds_ewon
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ewon."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0858562831f7cbb5b461ef0d73c68ead83f2c0910d0f2e0811b455f532653d208b43e3f93a5532508c7ebb70cd7e7be8bb53d58b4c7c69f0764990657f1c4e1b"
    $a1="0858562831f7cbb5b461ef0d73c68ead83f2c0910d0f2e0811b455f532653d208b43e3f93a5532508c7ebb70cd7e7be8bb53d58b4c7c69f0764990657f1c4e1b"
condition:
    ($a0 and $a1)
}