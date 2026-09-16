rule sha3_512_hashed_default_creds_dell
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for dell."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b92956a3364685ee38de61c588f054b20921d26c2a23f13ca0732d42d0f50e382f6a69f12adb37a2313657b2557e1c96dd90003e4f046ab16e1882e4edc8a70e"
    $a1="8cd824c700eb0c125fff40c8c185d14c5dfe7f32814afac079ba7c20d93bc3c082193243c420fed22ef2474fbb85880e7bc1ca772150a1f759f8ddebca77711f"
    $a2="e9a75486736a550af4fea861e2378305c4a555a05094dee1dca2f68afea49cc3a50e8de6ea131ea521311f4d6fb054a146e8282f8e35ff2e6368c1a62e909716"
    $a3="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a4="b2a5c00837730abc919b954106fa446e1335a4b2f457b1942928ed7231b3bd33615cd91cf2197447e8328cf07aadb0f58e68bf12c64f0928b21039ff52210362"
    $a5="8cd824c700eb0c125fff40c8c185d14c5dfe7f32814afac079ba7c20d93bc3c082193243c420fed22ef2474fbb85880e7bc1ca772150a1f759f8ddebca77711f"
    $a6="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a7="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a8="913bd2039c6ec7d97bbd358a16125367b4c8cc534fcdb6369a5419aa309d642ad43c2e7f5ecc7f7ae4ed3967c96c85bdf3663929d7d0b605d4a1c03b538fbe94"
    $a9="e34c71a03ea90304be4cc0b3c6356d5b6ef1596f97ee116ab205f616b70d1c6ee23a2d0276af6625ba658176e9ae9c92c3fef6686933dfde0efffd8d64a30494"
    $a10="c5385c68a309241ad34389489227e61cb2ad7191aa392e08d9582c540514263f268491def99f1f479c12b79c2b97d13bcfbcbd59f2937636177849b5d0314f36"
    $a11="91d9afe9c786478c48ae16d1e70d70498defc79d2a28979635d077095c4e2658d765d9b459eaaddfcb81d9c7eaca42314b9c04b34bb0118e50233a901d7504a8"
    $a12="600700053a68627643a47c88b59df33ad817ef4c2173af8d46893e5a91adb50775925f1bcbd7579942cbb04713a7157c8ecde6132db5e07f77a4b4fff733ae62"
    $a13="8cd824c700eb0c125fff40c8c185d14c5dfe7f32814afac079ba7c20d93bc3c082193243c420fed22ef2474fbb85880e7bc1ca772150a1f759f8ddebca77711f"
    $a14="9c15048bc812d9f22ecbad8eaf0677b43cb75d1865b50737e84879ec1adc1c819e728b92d11b2321243c1aa6ccb143ec241e476e4e2376cc888bbfe963e928a7"
    $a15="de919babf8aaa4b61eee7bb4d13c2b317977cc7552a2520041661b9babcd6dc542b8145a7b8efa5532c751887b99016fa3ab29acff4b7d99a3ba99d96eb22804"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}