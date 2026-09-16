rule sha3_512_hashed_default_creds_tiara
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tiara."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="11f8ba115294bfddd613264d0842061bd124ba8442facf3fe7b0f75a59ad32ef0caa2fc50b653106afa4447baa0ce0078a55d7d6ca37ef96b2cabe79d56cc196"
    $a1="eecc8c5c5c8268bd52440a00183fabec33ac6b2763214b19da54651f8017339d05c0f51dd02783bd4d3846147e192ae34062618c00ffc1a2c10248d43c6ee182"
condition:
    ($a0 and $a1)
}