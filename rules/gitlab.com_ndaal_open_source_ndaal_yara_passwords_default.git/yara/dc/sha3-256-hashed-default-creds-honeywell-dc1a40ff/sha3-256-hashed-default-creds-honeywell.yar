rule sha3_256_hashed_default_creds_honeywell
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for honeywell."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1d6442ddcfd9db1ff81df77cbefcd5afcc8c7ca952ab3101ede17a84b866d3f3"
    $a1="bdb3f8add40dad8b96492731a523f85358d8f3c3ec6458ba9c3aeb02fe8d48ab"
    $a2="1b9d3b1526324d37b28648c45cc8f21ad6eafd9a9eea3ebbe24b249a986023f7"
    $a3="56c42e2e7e039ed7d20fcf94b6ea70d383d912d389b510b24f008206ba85fd8c"
    $a4="e67822e59cdad773a782f84ad618c04955ebbfcd4879c75be1126287c7ec5edf"
    $a5="375617b0affce95ce069be5d690b962f3b5994e94ac350eb83d32d2b8b342c79"
    $a6="79b51d793989974dfb7ea33d388d0016dd93a6e80cdaaac8b34ec2f207c1b70f"
    $a7="2848f07d55acfdd67caf77f276e1f0a529e4026f1708356d77b1ced98326836e"
    $a8="4c678c8303c73293bfcccd1ac543ead33636fbb80427383371699c1cbfb339a3"
    $a9="58e7d8a8e0fcb4a85e4afb1a75368a97faf987e911e5d1a7bba43520603a2404"
    $a10="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a11="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}