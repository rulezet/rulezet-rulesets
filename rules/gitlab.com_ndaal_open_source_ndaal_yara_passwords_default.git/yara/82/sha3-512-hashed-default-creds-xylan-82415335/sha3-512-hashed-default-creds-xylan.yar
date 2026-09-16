rule sha3_512_hashed_default_creds_xylan
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for xylan."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e9a75486736a550af4fea861e2378305c4a555a05094dee1dca2f68afea49cc3a50e8de6ea131ea521311f4d6fb054a146e8282f8e35ff2e6368c1a62e909716"
    $a1="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a2="82d6d00febc1e0af849cc06ff5919fd9c980b94fc352d37741c348621be1331c716f6a4dd26b471b7497e67d5888544146cf31cd23b8305f55ecbc4b14540f43"
    $a3="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a4="82d6d00febc1e0af849cc06ff5919fd9c980b94fc352d37741c348621be1331c716f6a4dd26b471b7497e67d5888544146cf31cd23b8305f55ecbc4b14540f43"
    $a5="68d744c2fe5664432c594b937d4d920cf215cb39477be66c67a15b8720af33cec3d2ccc321230896a2655d8131f5dcafbf0afbc0e59edfb56a6adf174c4e3c80"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}