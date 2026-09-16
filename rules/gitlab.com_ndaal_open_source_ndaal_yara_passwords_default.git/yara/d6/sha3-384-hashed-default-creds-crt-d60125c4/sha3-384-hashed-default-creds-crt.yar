rule sha3_384_hashed_default_creds_crt
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for crt."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4989b42988dfd06632c28aa8737106a17f7103a60a6ea68c6ce9719e33ca6f9dcd72eae891bbf2b6386e3681942e3bfc"
    $a1="b7b9ed8b52ae23af2a8623b24d27356b7056c9be59fd5ed63910b2c59149528462f6869bca3606cdb566b64984eea323"
condition:
    ($a0 and $a1)
}