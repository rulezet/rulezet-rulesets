rule sha256_hashed_default_creds_weblogic_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for weblogic_web."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="04a81e6b4883fbf2553a5e9baf9a84b4502b1c1f67eedc4fb20e8f2458b663d4"
    $a1="04a81e6b4883fbf2553a5e9baf9a84b4502b1c1f67eedc4fb20e8f2458b663d4"
    $a2="5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
    $a3="7de97367c9cdc3c6db31aa114057b65cea1a7bafc71cf0595a2931011526a0a3"
    $a4="5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
    $a5="06e55b633481f7bb072957eabcf110c972e86691c3cfedabe088024bffe42f23"
    $a6="8443a814600766bbf5bc87725ebc9c7635651af65c3f67ef86a25d11e24559cc"
    $a7="06e55b633481f7bb072957eabcf110c972e86691c3cfedabe088024bffe42f23"
    $a8="d9262e7fb868c502061473089e5212378ac3935e2f96294266da6d7eec7d44e0"
    $a9="d9262e7fb868c502061473089e5212378ac3935e2f96294266da6d7eec7d44e0"
    $a10="6ee4a469cd4e91053847f5d3fcb61dbcc91e8f0ef10be7748da4c4a1ba382d17"
    $a11="bbc5e661e106c6dcd8dc6dd186454c2fcba3c710fb4d8e71a60c93eaf077f073"
    $a12="ab38eadaeb746599f2c1ee90f8267f31f467347462764a24d71ac1843ee77fe3"
    $a13="bbc5e661e106c6dcd8dc6dd186454c2fcba3c710fb4d8e71a60c93eaf077f073"
    $a14="5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
    $a15="bbc5e661e106c6dcd8dc6dd186454c2fcba3c710fb4d8e71a60c93eaf077f073"
    $a16="18fa5faf897b9b8c3375efb6fdb3ebcf56ba4442812c3df59fe791d8f6a897ef"
    $a17="bbc5e661e106c6dcd8dc6dd186454c2fcba3c710fb4d8e71a60c93eaf077f073"
    $a18="8443a814600766bbf5bc87725ebc9c7635651af65c3f67ef86a25d11e24559cc"
    $a19="8443a814600766bbf5bc87725ebc9c7635651af65c3f67ef86a25d11e24559cc"
    $a20="5a3bc29fe6c9cf21f71bc92ac2f00d3be32ef02d98fb831050866ef6031cc77c"
    $a21="5a3bc29fe6c9cf21f71bc92ac2f00d3be32ef02d98fb831050866ef6031cc77c"
    $a22="8298b9ec0d12459098a93234d4ff75a83e054f7254901a64939f9a4447793a07"
    $a23="8443a814600766bbf5bc87725ebc9c7635651af65c3f67ef86a25d11e24559cc"
    $a24="18fa5faf897b9b8c3375efb6fdb3ebcf56ba4442812c3df59fe791d8f6a897ef"
    $a25="8443a814600766bbf5bc87725ebc9c7635651af65c3f67ef86a25d11e24559cc"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23) or ($a24 and $a25)
}