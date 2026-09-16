rule sha3_512_hashed_default_creds_juniper
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for juniper."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="66aefb7dde2dac856807d63d2bda9d71568b7e6ad28c698bcbf0d725e61c72bc790064532977c1f714c9f1be28fa45253b8d91646d9160dc5f9aacd7a2d5ff29"
    $a1="66aefb7dde2dac856807d63d2bda9d71568b7e6ad28c698bcbf0d725e61c72bc790064532977c1f714c9f1be28fa45253b8d91646d9160dc5f9aacd7a2d5ff29"
    $a2="76e7d4dec7414f98d398948e38d0232cfa311fa1053ffd8a977a6a0fc2911ba81debbb577282eded9bf22ac2a7797e2dc2dfa8a1a72352988ceb80e7deb9a1ee"
    $a3="76e7d4dec7414f98d398948e38d0232cfa311fa1053ffd8a977a6a0fc2911ba81debbb577282eded9bf22ac2a7797e2dc2dfa8a1a72352988ceb80e7deb9a1ee"
    $a4="3274f8455be84b8c7d79f9bd93e6c8520d13f6bd2855f3bb9c006ca9f3cce25d4b924d0370f8af4e27a350fd2baeef58bc37e0f4e4a403fe64c98017fa012757"
    $a5="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a6="66aefb7dde2dac856807d63d2bda9d71568b7e6ad28c698bcbf0d725e61c72bc790064532977c1f714c9f1be28fa45253b8d91646d9160dc5f9aacd7a2d5ff29"
    $a7="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a8="343044eba1a91f0d960f6d74515841926409bd574a203089c491cf4591ea7c1b918b4c381c13ee0a77f42d7bb2e04d9e4d75a189db5d20d1c6780ad744d7ec6a"
    $a9="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a10="cfab24261aacfc33b29081381b843df5e7e5f69f230ac7f91a00f7bfaa468ceb439e2ff659ff401f9961487d379b710b48708a1ffb7538bf75999a3b1e86365e"
    $a11="cfab24261aacfc33b29081381b843df5e7e5f69f230ac7f91a00f7bfaa468ceb439e2ff659ff401f9961487d379b710b48708a1ffb7538bf75999a3b1e86365e"
    $a12="f00c644c174825d50278946c432d337ca61c711b102785c9fdfe1fe7f65a8b163d1087ce0f964d31b510a9ef8aef606eb22d0fcbe45f889548649919d3e907b1"
    $a13="a5cb39ab7a85e70d39ae78b734b0f42660126100c6d458fdd3f8e6b20ab8f73b2db2a02a0ca8d38d40b6b2544be6491243703c5770cbce76385c2e3a9c791f36"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}