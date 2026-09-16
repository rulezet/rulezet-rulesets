rule sha512_hashed_default_creds_zenitel
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for zenitel."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4c8f375fb928d6222b51558dc522951ed74509ac57582cc2f2232afb9ab3e88866bcedc74c22391af19355b62de80dd3010cda91df7e415bcde86bd14b4d5cdd"
    $a1="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a2="fe825c0a5afa030658d6d59578d4467b725abd50438693909cd3cf91dd0b408c922fbddf79c3613f63e9327da58db8e02db16fecb6370e52d7fc93a873016052"
    $a3="238b90e6e2382ddafadc35266b2fa9a371fb3962b675ccab1b5538321f469070d0f3762f29b21ac7ad772eb6bd299d09f8e75d38ed8b7067965d5d5f26ebc3f5"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}