rule sha3_512_hashed_default_creds_mitsubishi
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mitsubishi."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6a1d8ea16c3e216655584a73e7ff34cdd43b53580188d8c81d46a150b37cd60a8535fc61ab1c9d3f8f92c537773755cb920e4255edb1a940e28cfea3879258c0"
    $a1="6a1d8ea16c3e216655584a73e7ff34cdd43b53580188d8c81d46a150b37cd60a8535fc61ab1c9d3f8f92c537773755cb920e4255edb1a940e28cfea3879258c0"
    $a2="845bf9cda691594d82a31c6992d8497a46df1052ef25192d6aba4ee8672b4696f2ee3ba373f67c548dee77409a6848dcbead81aa12fe56b8cce44abd2344462a"
    $a3="845bf9cda691594d82a31c6992d8497a46df1052ef25192d6aba4ee8672b4696f2ee3ba373f67c548dee77409a6848dcbead81aa12fe56b8cce44abd2344462a"
    $a4="de4ca5f8774453c9f4de6dcd460201e621cdba7f0b6e152a049cde5b3a46c0fea58e6abb5347f9923b01244ffc37832e048918f5fcbfee745c86a444315160de"
    $a5="3a1042b612a907b2a776584598e1c9638c87f749821926e4568c7772009f5a305f03c1e1fa8fa83561bed14550828f1d9468b4f670d07d35f4ab97af1ad7d912"
    $a6="dee4164777a98291e138fcebcf7ea59a837226bc8388cd1cf694581586910a81d46f07b93c068f17eae5a8337201af7d51b3a888a6db41915d801cb15b6058e5"
    $a7="6a5bfbd98d1312047dc685888dc1fde0f998092f97068f484e7ba73032c604652aee25ad2c8dc6774c8a1d718d1e623b7b79390fcc5edd1c7802fbd793d7d6af"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}