rule sha3_384_hashed_default_creds_zte
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for zte."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f330280078eedee79f2d2cf5b6de1136984fc1ce5eba8452ecc283c1f84fbf60b968c2767a9407d5646f8c1e13890bfe"
    $a1="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a2="0dedff25a5e9d803773cb80953c7a962103da028a6c69b7a483426acb880d340a9b779eeb5ee3a738b0e83af859426f2"
    $a3="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a4="713d80421f781abcf2768f42fd1f17541c1fa03f68255d3d1fa4810590fdd77bb2a37d092f4b28fdfed380ba2dfafc7a"
    $a5="713d80421f781abcf2768f42fd1f17541c1fa03f68255d3d1fa4810590fdd77bb2a37d092f4b28fdfed380ba2dfafc7a"
    $a6="2a1caa6a50da964f85291200f3e4dd35f49a634dd18620d736457c69c297724187fbc448018cd480adc523f401322f65"
    $a7="3f96b2db838678ffa54c4e255c08b57b99e1ddae50ff8a0de2b2b44cf21f8c8d67e7ffddfddd9b09bda8df6c768c8ff4"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}