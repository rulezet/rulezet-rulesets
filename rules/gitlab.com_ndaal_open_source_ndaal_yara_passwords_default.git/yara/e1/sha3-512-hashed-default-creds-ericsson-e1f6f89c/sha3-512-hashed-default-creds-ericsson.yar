rule sha3_512_hashed_default_creds_ericsson
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ericsson."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f96b8c19c3e7f114833925bce79968bd9e75b8f15f3a6cd3858ceae6a97105fa0a22911ba45b9ab8cf840b447848e447a40c65a6b39457b979172633572b1ea0"
    $a1="f96b8c19c3e7f114833925bce79968bd9e75b8f15f3a6cd3858ceae6a97105fa0a22911ba45b9ab8cf840b447848e447a40c65a6b39457b979172633572b1ea0"
    $a2="fbaf1d3516e4849991e8eaa16e401a9d0cebad944297cd80022f9424c8d9d172f7cc94844f529cca51005498f56ca90672ca918cbbfc06c0071b9c12b98f89b6"
    $a3="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a4="dc2f4dabb854477fbedc841fa433e732db9309922075259d549ddcaa8df2c9421d55d154ebe9c3e65325a8524b7a823726da1d3020ae7477b30c787b707e8d31"
    $a5="65d69364a975c0a17dc28ac55ab29d2cc0b4cf0f013a993bcd9cfebffe3248077bc373763cf5de0a0467033f5a2e9da465e6792349abad8b20790708ef1298b9"
    $a6="5494b9ad0be108474a6dc8a92354ed94b0cf51c7092a28c7a201eaf94891d437a8638bba468c1b0ff625aa9b9e1415aed0943ce8c7be29a24511166b4a1dcec4"
    $a7="5494b9ad0be108474a6dc8a92354ed94b0cf51c7092a28c7a201eaf94891d437a8638bba468c1b0ff625aa9b9e1415aed0943ce8c7be29a24511166b4a1dcec4"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}