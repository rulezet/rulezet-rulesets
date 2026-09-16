rule sha3_384_hashed_default_creds_rodopi
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for rodopi."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a86f8458180791c36ef87727eecbe73b796df81714be28c23e73f6fa0808713c2b39b5e0699446205f3805ad17a84324"
    $a1="a86f8458180791c36ef87727eecbe73b796df81714be28c23e73f6fa0808713c2b39b5e0699446205f3805ad17a84324"
    $a2="c9c6d0620044eca7a8c12eb4054902606582b52b7e55990a65fe6944eef9a6a78b0cc9ef17084e927dc724310f422b8e"
    $a3="c9c6d0620044eca7a8c12eb4054902606582b52b7e55990a65fe6944eef9a6a78b0cc9ef17084e927dc724310f422b8e"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}