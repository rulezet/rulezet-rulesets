rule sha3_384_hashed_default_creds_postgres_postgres
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for postgres_postgres."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a1="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a2="9c1565e99afa2ce7800e96a73c125363c06697c5674d59f227b3368fd00b85ead506eefa90702673d873cb2c9357eafc"
    $a3="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a4="d1d974afe6993a728a48bb032fdaea8547a0b676f718b6c2ece8a583e98a20aa3b48ff211f88ca7b0116ee0e41bd62ff"
    $a5="510708f9246678a11f23ebc3320fa169663b13e17ec2652b136e3e5bff9ef6e602043c45690d4e9028c999fddfc80949"
    $a6="9bd942d1678a25d029b114306f5e1dae49fe8abeeacd03cfab0f156aa2e363c988b1c12803d4a8c9ba38fdc873e5f007"
    $a7="f4b956aaf8da19793edd03baf5de66672461717259212e03d599290bead33bd556c9c6fc193277a8bf0ca7c5bc3cddbe"
    $a8="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a9="f4b956aaf8da19793edd03baf5de66672461717259212e03d599290bead33bd556c9c6fc193277a8bf0ca7c5bc3cddbe"
    $a10="38d95059ad42bdbd28eed860428ccfd696fdfd2c9c05b2db074f019f981cc6af2a6793e38afcfdf9a3ad3b0a4b8c88a9"
    $a11="f4b956aaf8da19793edd03baf5de66672461717259212e03d599290bead33bd556c9c6fc193277a8bf0ca7c5bc3cddbe"
    $a12="9c1565e99afa2ce7800e96a73c125363c06697c5674d59f227b3368fd00b85ead506eefa90702673d873cb2c9357eafc"
    $a13="f4b956aaf8da19793edd03baf5de66672461717259212e03d599290bead33bd556c9c6fc193277a8bf0ca7c5bc3cddbe"
    $a14="f4b956aaf8da19793edd03baf5de66672461717259212e03d599290bead33bd556c9c6fc193277a8bf0ca7c5bc3cddbe"
    $a15="f4b956aaf8da19793edd03baf5de66672461717259212e03d599290bead33bd556c9c6fc193277a8bf0ca7c5bc3cddbe"
    $a16="a82957ea207016da5b14bc00f0484484c780f79dc1cc926538d7e4ef5f25e862ca95b129bb2ae3e7da2cf9ac195c237d"
    $a17="f4b956aaf8da19793edd03baf5de66672461717259212e03d599290bead33bd556c9c6fc193277a8bf0ca7c5bc3cddbe"
    $a18="ef4d0938d4736f1800f39a606219c2fbf2261e3b194ab2aefe283da6d0fbe62ed0083d1025bd2e12807393c0932ed684"
    $a19="f4b956aaf8da19793edd03baf5de66672461717259212e03d599290bead33bd556c9c6fc193277a8bf0ca7c5bc3cddbe"
    $a20="ef4d0938d4736f1800f39a606219c2fbf2261e3b194ab2aefe283da6d0fbe62ed0083d1025bd2e12807393c0932ed684"
    $a21="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a22="7cd3b5765fb19d9d3a5a085dbb031824e8261c7e3f622315f2b6efdcf7715cab24af15c59bdbb20ecbc03410e52a586a"
    $a23="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23)
}