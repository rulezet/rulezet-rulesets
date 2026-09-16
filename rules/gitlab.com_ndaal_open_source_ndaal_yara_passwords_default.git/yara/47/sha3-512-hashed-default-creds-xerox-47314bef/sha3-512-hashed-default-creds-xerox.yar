rule sha3_512_hashed_default_creds_xerox
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for xerox."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="326a0e6a2c968de52f44ef954b4da68b3f136b21f147e00c72ec21b4ee5a4829bb91509e24fbc9869b6265c45cc90c37bf3f50084994c485c8ed5e7afc70d289"
    $a1="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a2="cdef0c740bfc6224a650219c6266edcc491f6535c9444f21591423b95cc7d63344b2cf83e2c81f0143141f0659b3aa31996319b932fdcd6c4da531684bd58de9"
    $a3="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a4="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a5="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a6="2a967d7cf49ca20a07cc414ee5759ff02043e6ef92ae33a5174cd6f496ffc83d4a51e19109ce01a801d7b264947a0951a5f4c845a3aa8f3193dc540bda21caaa"
    $a7="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a8="326a0e6a2c968de52f44ef954b4da68b3f136b21f147e00c72ec21b4ee5a4829bb91509e24fbc9869b6265c45cc90c37bf3f50084994c485c8ed5e7afc70d289"
    $a9="7d6e49927bdd21d4bd76b0fa6d3afd1d5edc89d464e0e867e32b8948fc0a83a4dcef3936a325a227c77bcb5ab97e76f3f4006b97c0f8ccdeb89a24f05b505aa9"
    $a10="21f9ff061b755faaa06d71434f31330582901810871c228a4d67f9e52f2adf82ea6b445bb4c98d49da68fb140717911e4fc5e1c49ec0becf0aadec0f7517f8bc"
    $a11="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a12="31ff452e79f34fd0da4d15ae598b46c22e9a1cb82eb9f583fd34b0f055a5b6c560f6b75ffd25d5a9011f2e259196d93c68907493721b2649c3b4205aa07407dc"
    $a13="e34c71a03ea90304be4cc0b3c6356d5b6ef1596f97ee116ab205f616b70d1c6ee23a2d0276af6625ba658176e9ae9c92c3fef6686933dfde0efffd8d64a30494"
    $a14="b91bb075d94f28437123f17ccb8904f1108f1e1236286cd3d0452fbacca43d06ef593990cc11127f98157e13d7937e71b7a7414f7510078d85fce664a3d115f4"
    $a15="4c6ba600c61e4f53a86d168277e328d2825e870a5211104f221af4a639a68e940f952627bc6c64742cb155ec16bbb5b0c73c3b26d1c764877059c019eab5dabf"
    $a16="35777b1e4eb9b8e68d1ad46b4ddf0ffdf6abd5234a963d580827586dd72713b99e274b301e2de7c3a20fc819bb2c09c82c304d7d0baf5c869df81668165d5298"
    $a17="00efa2d4f6e53ad2b0e0232bac91e7175b8d58298eac815b382ce2685da170effab4b9b3d924157ca36c2be3debe0368c8ad559689ee7e6b4024a38f4cdb9962"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}