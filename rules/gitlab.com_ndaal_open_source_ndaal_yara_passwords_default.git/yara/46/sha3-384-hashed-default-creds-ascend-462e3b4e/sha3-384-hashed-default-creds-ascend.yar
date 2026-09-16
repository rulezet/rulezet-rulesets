rule sha3_384_hashed_default_creds_ascend
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ascend."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b35410f11c81b31198871c612d05639757dc8a279ed5c8c663a5d9683969d85704b1316f47b1cc0168711735088580a4"
    $a1="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a2="a741e81d56af5d8d8989246b020b6511ca94eab702c084079afd8a0493d6231f66c3a7ea7a86c37bb61597d4956bb8aa"
    $a3="aac595410801e93eadb099ac575ccc12e43be2c15e31e7991e908329e5beb0729881b3be9ccdb0eeb6eb79335ea38b6d"
    $a4="59a8a0053065fe4eaa6942c9eea9ba79846a14e747a11c9039779239e63b346f7bd3439514164f573ed9c4c0ec37b89e"
    $a5="0e08ace98462c032a1d1ef35387532a39d62bf837abfdfd1ac221c6a070fe0e064ce07d88c6004e63d55d1fa8d508327"
    $a6="a53f652c63106cc8e536222155fb49f98e6071e10f0a523b81ec1359d1d2ab8351fcf141a3442ccad71de87fa1f18efd"
    $a7="efd9e5ef02a9405c6da4dd3b8451f61834c6c444d2ff6654a29a2c4709e69d98815377874349b9d9189f72527b2216df"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}