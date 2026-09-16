rule sha3_512_hashed_default_creds_wyse
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for wyse."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="600700053a68627643a47c88b59df33ad817ef4c2173af8d46893e5a91adb50775925f1bcbd7579942cbb04713a7157c8ecde6132db5e07f77a4b4fff733ae62"
    $a1="8cd824c700eb0c125fff40c8c185d14c5dfe7f32814afac079ba7c20d93bc3c082193243c420fed22ef2474fbb85880e7bc1ca772150a1f759f8ddebca77711f"
    $a2="9c15048bc812d9f22ecbad8eaf0677b43cb75d1865b50737e84879ec1adc1c819e728b92d11b2321243c1aa6ccb143ec241e476e4e2376cc888bbfe963e928a7"
    $a3="de919babf8aaa4b61eee7bb4d13c2b317977cc7552a2520041661b9babcd6dc542b8145a7b8efa5532c751887b99016fa3ab29acff4b7d99a3ba99d96eb22804"
    $a4="c5385c68a309241ad34389489227e61cb2ad7191aa392e08d9582c540514263f268491def99f1f479c12b79c2b97d13bcfbcbd59f2937636177849b5d0314f36"
    $a5="91d9afe9c786478c48ae16d1e70d70498defc79d2a28979635d077095c4e2658d765d9b459eaaddfcb81d9c7eaca42314b9c04b34bb0118e50233a901d7504a8"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}