rule sha3_512_hashed_default_creds_openconnect
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for openconnect."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0370a17f310db92409df517c78f93f3033dc09b066c7e62b3e8ddafeb6b85d5860ff9b036e986a43a2fc8109923bd1cdab08f60a8770369f85e9d350b1819883"
    $a1="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a2="0370a17f310db92409df517c78f93f3033dc09b066c7e62b3e8ddafeb6b85d5860ff9b036e986a43a2fc8109923bd1cdab08f60a8770369f85e9d350b1819883"
    $a3="92a04f9414a125c33f46245693b43ed71341ef8186d7182f2d6599a769bd70a231c739ce3b5461145f3aaf4ca48ed298086e3ea30e0c4347cd27dc4560cbf02c"
    $a4="0370a17f310db92409df517c78f93f3033dc09b066c7e62b3e8ddafeb6b85d5860ff9b036e986a43a2fc8109923bd1cdab08f60a8770369f85e9d350b1819883"
    $a5="0a58894a41dd11073057b983dee7d5ca7699afbed2ef4703c6704bfb934f8a81bcb588e64d2cf7dca3a69b7ead0cdbb657b8e9c66c2eb3a0ed021f5695c69cf8"
    $a6="0370a17f310db92409df517c78f93f3033dc09b066c7e62b3e8ddafeb6b85d5860ff9b036e986a43a2fc8109923bd1cdab08f60a8770369f85e9d350b1819883"
    $a7="df93662f33e0d941e8722f19e52cab59aa5618f2a44fa1fc1076b8cd8deac32290cda053e99eb7ad2083960c115a9f0dfe2377b2beaa23a16fac7c42c9cba63a"
    $a8="0370a17f310db92409df517c78f93f3033dc09b066c7e62b3e8ddafeb6b85d5860ff9b036e986a43a2fc8109923bd1cdab08f60a8770369f85e9d350b1819883"
    $a9="7fde68d4de587aa17c5259103cfeb4720c4c2324e8c75df0f87a9c34a2ed5199b2b403f20be568e70d9a2ff54c42a24efc6c3abdf023b8fa44369bcb3b22f2ff"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}