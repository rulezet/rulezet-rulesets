rule sha3_384_hashed_default_creds_juniper_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for juniper_ssh."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e07300227b15a724fdf6555569e38282022d106d778aa2268898dc21639b24e1e00fcc0a6d96ffc8b3a97c7fa7296305"
    $a1="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a2="c5953e0f9d2f428cc2e39d004c4e3fce7383c4a94b08fb5d2847ec5e60073b669c9b9ea515ec173bb23bf366b5f56f29"
    $a3="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a4="8ec9de56e89a5103fc2307816c7ec4b5b3c4ad29a2ba8d219e1864b5ba041798fcef6de0004b155e69ec41975d24f2dc"
    $a5="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a6="c5953e0f9d2f428cc2e39d004c4e3fce7383c4a94b08fb5d2847ec5e60073b669c9b9ea515ec173bb23bf366b5f56f29"
    $a7="c5953e0f9d2f428cc2e39d004c4e3fce7383c4a94b08fb5d2847ec5e60073b669c9b9ea515ec173bb23bf366b5f56f29"
    $a8="7402910b87f2e5294a29e2a5388a2908f98aea5a20f1e4e1074bd67e4d11c182c2a709d7772ac1b05c5d66c7011d7ec8"
    $a9="7402910b87f2e5294a29e2a5388a2908f98aea5a20f1e4e1074bd67e4d11c182c2a709d7772ac1b05c5d66c7011d7ec8"
    $a10="33ce5107b40988a8734c41e3cba1b8f6e4f6da52d6799d6387ce87d6f50c4a47041adfecc4fbe88a3b2c2a18764724e3"
    $a11="33ce5107b40988a8734c41e3cba1b8f6e4f6da52d6799d6387ce87d6f50c4a47041adfecc4fbe88a3b2c2a18764724e3"
    $a12="e571cf56bb1b8c66f560c4f729627feba4863b5ecfd75b7eaa4c5e8b1d92a614214eb0981dfdb5675d39db73b3c0d4ad"
    $a13="a42d04a5b4a2ea45ecf45279aaf3ec8fd906355e3ab856231ae7815a5df6a96f76fe4987dd638981314c942ba825de69"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}