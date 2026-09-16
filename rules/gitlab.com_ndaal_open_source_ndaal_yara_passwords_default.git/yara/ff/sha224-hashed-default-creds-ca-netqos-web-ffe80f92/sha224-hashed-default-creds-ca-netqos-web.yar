rule sha224_hashed_default_creds_ca_netqos_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ca_netqos_web."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5f9da6777dcee86e3b0c3fdff90eb7239580415da08cb2bc632a5323"
    $a1="ea324e0ac4777e58a92387912c5b505d7d0a6f5db9d39c445d7ecb90"
    $a2="5f9da6777dcee86e3b0c3fdff90eb7239580415da08cb2bc632a5323"
    $a3="f6eb53fd205295c3a4e2bd7c419c880872e73bdb279b7ea91c4b856e"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}