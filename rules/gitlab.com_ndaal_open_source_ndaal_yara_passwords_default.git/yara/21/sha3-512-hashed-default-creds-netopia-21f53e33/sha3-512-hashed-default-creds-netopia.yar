rule sha3_512_hashed_default_creds_netopia
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for netopia."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="66a646f62cf6febbf71c02724d0019e878e44f06de95233dff368d6c241322ac57268597f79542486ac5757876f77722e73698bf7ffb29fdf2f3717b8c67dd9f"
    $a1="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a2="d477031231112e4e5328469d4af80d8771c394026160f82fb47c281bd877c1b9a19757081e3cbd68b3ffd86f32edad1f5076eda087e9bd7fc91317fb0fc94063"
    $a3="d477031231112e4e5328469d4af80d8771c394026160f82fb47c281bd877c1b9a19757081e3cbd68b3ffd86f32edad1f5076eda087e9bd7fc91317fb0fc94063"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}