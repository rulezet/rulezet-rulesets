rule blake2b_hashed_default_creds_textportal
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for textportal."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8b28f613fa1ccdb1d303704839a0bb196424f425badfa4e4f43808f6812b6bcc0ae43374383bb6e46294d08155a64acbad92084387c73f696f00368ea106ebb4"
    $a1="db9a9aa90aac7a90da5ab69692155d9330fbfe70c91885b74a91eb395e501694e1bdda76a82319ced1d31e774695142e879ca8db8a85bfc10ae85739580aa28c"
    $a2="8b28f613fa1ccdb1d303704839a0bb196424f425badfa4e4f43808f6812b6bcc0ae43374383bb6e46294d08155a64acbad92084387c73f696f00368ea106ebb4"
    $a3="42b724c893cba0ea966c99f19daf354d70c7c2f5661644d6160d1b26f90ba823eedd7e13e05cfafb8bfeda5aa63c3f7c709fd904064f9f676be5ef9c76adcaee"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}