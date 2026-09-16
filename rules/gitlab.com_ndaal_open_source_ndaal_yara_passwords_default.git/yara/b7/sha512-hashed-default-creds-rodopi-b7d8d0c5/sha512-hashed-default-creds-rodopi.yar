rule sha512_hashed_default_creds_rodopi
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for rodopi."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1a77f4fb127a0e45f099b42ff6ef8ba06b6d35cd400791009cacef09a7074f4398af0bfabddddd58d62d8565cb1e4007a3bf66c3eee1d0fa639c0269e81e26e3"
    $a1="1a77f4fb127a0e45f099b42ff6ef8ba06b6d35cd400791009cacef09a7074f4398af0bfabddddd58d62d8565cb1e4007a3bf66c3eee1d0fa639c0269e81e26e3"
    $a2="45b70e8b82b3db309e718914484c04eded60b99ea85bc1426c6184526cb9c2cd0246070620d6a618a476a624f9af7508ae94d132ecb16b6849cf875cfa6b5817"
    $a3="45b70e8b82b3db309e718914484c04eded60b99ea85bc1426c6184526cb9c2cd0246070620d6a618a476a624f9af7508ae94d132ecb16b6849cf875cfa6b5817"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}