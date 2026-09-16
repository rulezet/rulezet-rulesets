rule sha256_hashed_default_creds_honeywell
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for honeywell."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="03ac674216f3e15c761ee1a5e255f067953623c8b388b4459e13f978d7c846f4"
    $a1="4194d1706ed1f408d5e02d672777019f4d5385c766a8c6ca8acba3167d36a7b9"
    $a2="47e5a6cd5d35ae54f7d54b91f1101f8cd19e16d4de81987aebb1797781e57bc8"
    $a3="442e67f339040c13865fa8306cbfff3dbf789f62be42aff7f866f24f20ec9946"
    $a4="210d00ae954a907a9ce1b06c663f702917a6823ccbddd986e9f0a21f51e2af27"
    $a5="8b10163df5c8c0e1068927b0de7b040e8d567f4176da083a2ec059c4b0a36e1c"
    $a6="84983c60f7daadc1cb8698621f802c0d9f9a3c3c295c810748fb048115c186ec"
    $a7="5ed8944a85a9763fd315852f448cb7de36c5e928e13b3be427f98f7dc455f141"
    $a8="a55e2e3846a51f6ad0abfdfbdea2ba0e5e0c76b5ccfa8a920895fedeae89a8b6"
    $a9="251d0b11767b751b455af313681b863bef8a9388cda14a5203fcb15215c610ed"
    $a10="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a11="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}