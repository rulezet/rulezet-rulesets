rule sha3_512_hashed_default_creds_telebit
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for telebit."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ae0380de40c9c59e8e0455a4272e9f74bad7dd08108e5fd44c09eaef705ef5b8ee2aba8152b186f067c2235a197f3c88af2010bba3a610ff60c7ac2f8c35b4b7"
    $a1="ae0380de40c9c59e8e0455a4272e9f74bad7dd08108e5fd44c09eaef705ef5b8ee2aba8152b186f067c2235a197f3c88af2010bba3a610ff60c7ac2f8c35b4b7"
    $a2="4da5e755ba5f6f7c50c35a026cce0ad2502305444d99ed680925fa90cfb3de48b537855d6e554ea0ac808eb6a1bbc853476065ed79b768b371868482bb0f4718"
    $a3="3544701b1b3c664c4bde932492c6ef3bef31dbe7d16ad4a0ffd1fbae0e91cce47280684989f6353e129438011bface3102304efc6df34585241148b5d94f2977"
    $a4="d8daf7b12c0ad18465b4804f8889649405fbe2ca3caa3b54a2dd1ea0ea5b41b56fd8df455308ff67212267a4ac45c109a2b0076680c39f347939228bdc640950"
    $a5="3544701b1b3c664c4bde932492c6ef3bef31dbe7d16ad4a0ffd1fbae0e91cce47280684989f6353e129438011bface3102304efc6df34585241148b5d94f2977"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}