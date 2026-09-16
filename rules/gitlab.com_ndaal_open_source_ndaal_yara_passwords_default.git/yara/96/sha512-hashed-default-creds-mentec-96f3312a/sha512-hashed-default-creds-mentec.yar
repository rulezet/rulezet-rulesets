rule sha512_hashed_default_creds_mentec
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mentec."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f184565468795cb530cc19cb510a9fe6307017052152a44ba5ddbe5858f00fd38aec6b0e414831522d938263f83ec1c23d41b956b637387d8714ceb4f85e8c37"
    $a1="5cc61365b6a4bc604af55a81ac49d26c41a437b1f098d4c3085586cb586e5ab7ac8c691d09658c5c5b586f0a0b1bfcb883bf141ba2719f89c4518b672bf90c81"
condition:
    ($a0 and $a1)
}