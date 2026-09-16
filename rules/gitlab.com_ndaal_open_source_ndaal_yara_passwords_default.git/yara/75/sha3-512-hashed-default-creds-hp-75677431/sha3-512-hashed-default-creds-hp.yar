rule sha3_512_hashed_default_creds_hp
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for hp."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e9a75486736a550af4fea861e2378305c4a555a05094dee1dca2f68afea49cc3a50e8de6ea131ea521311f4d6fb054a146e8282f8e35ff2e6368c1a62e909716"
    $a1="8cd824c700eb0c125fff40c8c185d14c5dfe7f32814afac079ba7c20d93bc3c082193243c420fed22ef2474fbb85880e7bc1ca772150a1f759f8ddebca77711f"
    $a2="bb0dfb861aaa288bdc3e61b86311c7d98c8b8ab2b4e603e8868f2b22485655eb7faff92021c8bb2d88dc99c028309e7ba2313817c0fdff46b49c5ead46d5161e"
    $a3="8143d62fff557e3c37e15a7e7e1be8dd031401cd55da9ca74237e70f8c9d0f20bad8a2af7b22986e56ee6a704ee365f79f83fe7fbfe0c359d7caecc8030f6af5"
    $a4="465af57d67bc6c4e26c1a5a1e30ccf6f01e5f995dfb90e831738bc15e8f46acf2cbf814b9f835234dd30eb3f902013e51b9f0bd770d0c792cc55b5c2b916d0be"
    $a5="736eb3ca25c23ad0861cd1b5676b8b2eb2aeef20d38a63edee2c56cff4b8582da93314a9be1bb60760ceb989026e9e01ac2458be97dff16e208e932b7110ffa5"
    $a6="ac45cdffe5f1a2fc06b930dfb2a99b26682e04e2228da715d7f464eb4e06d7a9985ae7d667f6cd8ed96576de78aa4121445fec3efc2c1e97b6cdbb77d7b84ec4"
    $a7="736eb3ca25c23ad0861cd1b5676b8b2eb2aeef20d38a63edee2c56cff4b8582da93314a9be1bb60760ceb989026e9e01ac2458be97dff16e208e932b7110ffa5"
    $a8="8e8bcc6d85575a8f0dfac2cb0e3eb28abff83f81d14304d260ed87ecb4bc046f94b55e7b485d6e88978e9b5ff167c726ff7c11e4c451ac0778fb8c5188d34e6c"
    $a9="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a10="d887a0e79eb31a236584b5fbc521b86fb5fd317e9d5b381844d65da4e4f318bd354699208fd8f155f70e471e9a5048b815292fdc1f8b772d37410049a9cd1d89"
    $a11="6884d4025cc74257c32e357331c3c876da1609b7009d612d0da5197881e101efceaba542ea7fe1d216d3886a972723ad3cda8865585c29bba6711ceaa23a9525"
    $a12="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a13="e34c71a03ea90304be4cc0b3c6356d5b6ef1596f97ee116ab205f616b70d1c6ee23a2d0276af6625ba658176e9ae9c92c3fef6686933dfde0efffd8d64a30494"
    $a14="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a15="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a16="a5c2b610ebdb37ccd67781dbef1f802d70477c14ea2862a0a47a0de8c59eefd6b0d52e7775f5b454583fdcc8b3f8ac5bcace2037da7f7fd1ba03286069a701a7"
    $a17="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}