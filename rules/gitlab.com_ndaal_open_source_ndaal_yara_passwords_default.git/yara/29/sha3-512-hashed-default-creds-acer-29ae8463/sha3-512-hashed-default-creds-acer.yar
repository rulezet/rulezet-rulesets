rule sha3_512_hashed_default_creds_acer
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for acer."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5c854940114cc79363911683ad83bbf9e967dc613eeca7bf03590d8ef5da38e4bedffa091132c0c68effa6c51ba6db11a0fc712f8ab73bd5d511c8d36dd861b6"
    $a1="5c854940114cc79363911683ad83bbf9e967dc613eeca7bf03590d8ef5da38e4bedffa091132c0c68effa6c51ba6db11a0fc712f8ab73bd5d511c8d36dd861b6"
condition:
    ($a0 and $a1)
}