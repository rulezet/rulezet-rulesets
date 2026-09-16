rule blake2b_hashed_default_creds_mitel_networks
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mitel_networks."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="aa3f95a275a470327cd92c994e7559f5a914267407b70a3d6208e02735a9bbcd16b39f1cbc1b4be5ba697c1d27c605c69839ee6eac78bc02e9411af6f9bef763"
    $a1="3ad21c6f9def1be68a1795b8eb806e89674f92fda21bcac464a6b9e2fbb58547f097465fb0ceed6f6073dfb3783d06dd9938c55ee4ce6c6aa01e008d4bd27df7"
    $a2="b9e5a4b81102c413380132162c60d18799a0b6d0b9be318a19fec2fb58a784133aa29ddb07a8a37def8475c3eda324937632c26528ec7fa9dc0b419f7d5672b1"
    $a3="78029416f2a036f9bbee2b4519a452479916558edd66a43816bcce88d4b0269a8bb63062747ee448b35fdd05b00abeaf5003014087011ff134b7a00487caaccd"
    $a4="b9e5a4b81102c413380132162c60d18799a0b6d0b9be318a19fec2fb58a784133aa29ddb07a8a37def8475c3eda324937632c26528ec7fa9dc0b419f7d5672b1"
    $a5="0ac166e3f28df968b3fad02990833565556d765edd407bef1485057dcd212b7037a2aa983b3531acb5676f8863f1920b2e438bae55f3b69bb1800d63b9d2b8db"
    $a6="b9e5a4b81102c413380132162c60d18799a0b6d0b9be318a19fec2fb58a784133aa29ddb07a8a37def8475c3eda324937632c26528ec7fa9dc0b419f7d5672b1"
    $a7="fc21b2a2719697e3ea82b1ce2adad3d78185bfc8d6167419456d087402ecb6df7b24804440ee086e25eadadd5ea318b5dc789d187face78765f27daaf9ced286"
    $a8="aa3f95a275a470327cd92c994e7559f5a914267407b70a3d6208e02735a9bbcd16b39f1cbc1b4be5ba697c1d27c605c69839ee6eac78bc02e9411af6f9bef763"
    $a9="e48f30c4dd242f51b2256ce3b67b26058e1de9986ec812d87a2452e7803a63d9924ae7c0193e8f75b03f4651bd113b00245804652cd865a36c0b8d29dc5eb3dc"
    $a10="b9e5a4b81102c413380132162c60d18799a0b6d0b9be318a19fec2fb58a784133aa29ddb07a8a37def8475c3eda324937632c26528ec7fa9dc0b419f7d5672b1"
    $a11="238c8c11f3d51d2304c78be26341850c0a118fbb4a581016ffc5a161b8cb7992715d0c90a69563cdf78be6bd954fe379c2dfaa3fe44117ce11e5bfc7b801edf4"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}