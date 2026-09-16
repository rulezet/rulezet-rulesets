rule sha3_384_hashed_default_creds_zte_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for zte_ssh."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a1="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a2="d70b43000387175a14486f5c933e4f8012eb5bb0b00bf08fff9fb45165d4a315f9428b6d55062a91acc0e826bffbfc21"
    $a3="d70b43000387175a14486f5c933e4f8012eb5bb0b00bf08fff9fb45165d4a315f9428b6d55062a91acc0e826bffbfc21"
    $a4="95b2039bc45247a8d9617da94012665ceec1de90ad5b510a2018029549b36a953ece3c93de238b50b784c02214f69d8d"
    $a5="aac595410801e93eadb099ac575ccc12e43be2c15e31e7991e908329e5beb0729881b3be9ccdb0eeb6eb79335ea38b6d"
    $a6="d3f94093942fa4baac771b17420a427d7cb6ace21505571b94ea14a4da4f7f66f7045a6622cf10fdeb754b8f132170f2"
    $a7="aac595410801e93eadb099ac575ccc12e43be2c15e31e7991e908329e5beb0729881b3be9ccdb0eeb6eb79335ea38b6d"
    $a8="713d80421f781abcf2768f42fd1f17541c1fa03f68255d3d1fa4810590fdd77bb2a37d092f4b28fdfed380ba2dfafc7a"
    $a9="713d80421f781abcf2768f42fd1f17541c1fa03f68255d3d1fa4810590fdd77bb2a37d092f4b28fdfed380ba2dfafc7a"
    $a10="4c6c82392b1cac509ea7f0ca3bab653ec705278ef6b93843e4ca124ee859d335ba2ae7971a3f2d409bb9fda6110e3960"
    $a11="4c6c82392b1cac509ea7f0ca3bab653ec705278ef6b93843e4ca124ee859d335ba2ae7971a3f2d409bb9fda6110e3960"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}