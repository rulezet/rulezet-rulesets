rule sha3_384_hashed_default_creds_sitecore_corporation
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sitecore_corporation."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0c851fd986de48f9703a157327512d705e0aec5e339b53d99f4f3d55b02bd81a513e3ab059d20a348c993acd6591d347"
    $a1="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a2="1815f774f320491b48569efec794d249eeb59aae46d22bf77dafe25c5edc28d7ea44f93ee1234aa88f61c91912a4ccd9"
    $a3="7146d7c58cbf33a2c1ae20b887b2b879805ff93c7ccf23d0dfe7763239daa3519e94ae23513599865f1195046dd1496c"
    $a4="0c851fd986de48f9703a157327512d705e0aec5e339b53d99f4f3d55b02bd81a513e3ab059d20a348c993acd6591d347"
    $a5="7c9f4caca7cada9652cc8248b8e5f8bd80db16d4a4dc0b794865f60cd4e2a4bac1806f782fb1e2f338bf5fa0658456a4"
    $a6="0312ab38cafbaa6fffe82ab1aeafcce1d4c656c5fde60444232a374df23d6c364c4f33bb044ae258e25111227c9d57da"
    $a7="6b7949e10c6c429a4dc39190d777e7dab950e249cb4d076da592574424f05e170d5b668cff909ded062326ac24e69934"
    $a8="d1a95dab99bdfc5e1f48213027c463387c617881903985572d43433b4e4d8d21e0906abb58c2e4a633cc16abba1a9663"
    $a9="aa2075577b7f3e85c514cde5d5b99c080468b5da62bd2f63e8e1a655e73cbb7341f7aa5dda60b92877135b99149290ef"
    $a10="5428b66b2021a5090995a9f4964f8f82fb34712d4a10f69f1bfff92f8534e3939d86c83b441fb83bb937055733b9e6d9"
    $a11="cfeb5fd3c737c80d05a8cc9d2336cd7315f296f2ac127a76abc8470d78c21a32fec48dadba84d760ef7543a4f74f5d83"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}