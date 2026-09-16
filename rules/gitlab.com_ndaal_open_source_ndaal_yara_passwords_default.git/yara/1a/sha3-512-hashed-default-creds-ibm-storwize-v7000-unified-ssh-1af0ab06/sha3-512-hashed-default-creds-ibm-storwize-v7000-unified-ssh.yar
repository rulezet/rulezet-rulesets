rule sha3_512_hashed_default_creds_ibm_storwize_v7000_unified_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ibm_storwize_v7000_unified_ssh."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3d5b40da04e01be337d8bbdb7d6fece6c441696f43b22f3a28f5211786b0b1f11deb5c4851b395ef583dddfe13b55d5eea989577ff98f8c32903231fca38146c"
    $a1="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a2="4bdc214c7bba4a88527d78c8086746d18e8639d8f5b7a9f1ec105a3d002a3002fc05d98967fc68d0edaab6cec7fe46775ef8ba79db251bbfcacc098dad6ce083"
    $a3="8cd824c700eb0c125fff40c8c185d14c5dfe7f32814afac079ba7c20d93bc3c082193243c420fed22ef2474fbb85880e7bc1ca772150a1f759f8ddebca77711f"
    $a4="a9d14097c6b60a6c07a8d7b02b48feac60e83f43e59122ad00cad8122c492eec52f4590a18b733b909e3f17f2fa555012254b1ef6800ab815eb36a4098079532"
    $a5="8ca722b033b8e0f65c3373879389c8265599889ba6ff331528f1543a804cd2a1692573b0a09be80e70f7ed8a49958cc2da2d04cde5d0d3d0ac56dc246aa05481"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}