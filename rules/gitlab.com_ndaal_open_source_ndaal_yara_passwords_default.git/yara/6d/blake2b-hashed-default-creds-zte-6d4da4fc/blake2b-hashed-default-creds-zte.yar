rule blake2b_hashed_default_creds_zte
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for zte."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="23524a214912c6ed56056f056fd8fc39bd3335d7ddb19a6e3d6fc7687fb7d7e5ce2e9ddd4e6813c895ee0f64cb8b80176c6c48ab54e106ffd5aa548afccbbbbc"
    $a1="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a2="8ec48dee3fa5e834e5fa9df6a246e28e23b56ba54efbd01df3d72e89ee2e7bf9978afc3672be0861b1b6a6baea46cc079204f93dc2def62f9caa34224f8d806a"
    $a3="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a4="7c4c19165f106d9de2fcb67a6f4d907be2fa7776b1149ff82b69aa74348c0605ea4ef749ce4f5c2ace34cef80a0ce14a480284aa9b6463317b42a11efb64ec38"
    $a5="7c4c19165f106d9de2fcb67a6f4d907be2fa7776b1149ff82b69aa74348c0605ea4ef749ce4f5c2ace34cef80a0ce14a480284aa9b6463317b42a11efb64ec38"
    $a6="708bfd626e1068239a806708995e69de6dd7e9b8dd4498e3576badb863cbda0f4adf7d2b9228a187958e8c73cfd1f8515b713628b00e52e0d1adad35143a38da"
    $a7="5e42125e70ceb375f8af88ed9c0fd8af0ce4012df0ca3091251840e355dc39dc6bdc380937aafb0e546b9c9caf025568c8560922cf7568e9ed6188ec0aafe187"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}