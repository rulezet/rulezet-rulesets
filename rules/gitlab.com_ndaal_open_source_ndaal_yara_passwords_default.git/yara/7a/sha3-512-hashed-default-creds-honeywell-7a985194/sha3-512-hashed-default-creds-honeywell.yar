rule sha3_512_hashed_default_creds_honeywell
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for honeywell."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d760688da522b4dc3350e6fb68961b0934f911c7d0ff337438cabf4608789ba94ce70b6601d7e08a279ef088716c4b1913b984513fea4c557d404d0598d4f2f1"
    $a1="2eef495e66d4871eb926902e7d6051aeba80d971a46c1c15afbbaa8931bb3010da7f56f92aa6c0e53f39115f4b6e6f78c2f64b66e9cdba9e15edd2d8e0aaaa60"
    $a2="4f746af90aec8458b722248c8c015f8bd8b916bfc4eb07286f86cf9bf5468d8261cf0327ddedb612812ab5006620484625418e4919c81a1d399034270b4da79d"
    $a3="c0e18f2eb2eac30e7e30e20b5f5202f3ecbda35d5921b552b5dfdeff22761585cae92fc6ca496f136056d411350a4a10beaee5aaf29c56240679f5c38b8a780d"
    $a4="9328c5f4ecfdc43027ecc941ae17eb0a2c015e6a75109a01ee123c0af2cd8944b90ca506a2240d460e3d5607090a6e046d6e421143362e630ade139fe58d18eb"
    $a5="7390534efdf99c13932a57e08d226d44ccf8ecba0091ba8866b848fcec8d2437be3bd03ad1f0afa38c6b2057c4152b3fa36070a811ba67f6f1ddd008f0780fb7"
    $a6="6a5bfbd98d1312047dc685888dc1fde0f998092f97068f484e7ba73032c604652aee25ad2c8dc6774c8a1d718d1e623b7b79390fcc5edd1c7802fbd793d7d6af"
    $a7="90f2e09d2bbcaec0bf162a060461aa3f49647fec9cd87f0df9ea028e723ce3723fd47026b152f9fadf7af211cec81c285b8223199bce57ceb7aeafa60752a100"
    $a8="7ebf2ec2873c61214592fda44f3b6d2117867a908545d19677179219aed9251622b222ca60e3555d2685ede7e8227affd37404dffa5f54acdb269387ded70896"
    $a9="9f3d24b152bdd8874d0f6914ea5051ea21bf8a24589b41c57365884e82b0f95d09dfa1b5ddf862f42f5a001a56720e6fab1b8010a677f8abc7d07d9f5bd1f875"
    $a10="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a11="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}