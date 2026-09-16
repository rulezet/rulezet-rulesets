rule sha3_512_hashed_default_creds_t_com
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for t_com."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4c8a9532ba293aa52622af9eafc355033a0c338332dab40f7d2eb0d014e51e10fb9c59e6512c0ac2574429ecfb5004e1da0d45359b050d05e861c1b6730cca2a"
    $a1="87bafba4e031e3cf652e049c75c3975a1c822bf6573356a4a58c2945b76efe2c80c2b3f7490c35dd1b371cba158d995110e80713708b1b1f82f6fc523b0d3995"
condition:
    ($a0 and $a1)
}