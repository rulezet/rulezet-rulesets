rule blake2b_hashed_default_creds_psion_teklogix
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for psion_teklogix."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="24014add8e4640087f9d97ac298770a63ca6dec45da3bde89c8d30c0a642cc4ca7d8653213629f5fe18aba923fe50fc780837bdc7ea7aa7c26b390a91fbf6056"
    $a1="4ac3be53cae69554238d87f3c554d542c89f70b27ff17cbb11ecf83b5f1d6448738bf96c9682bf20a0b78963a532341834de37669223fbc41e1404bdc14efee2"
condition:
    ($a0 and $a1)
}