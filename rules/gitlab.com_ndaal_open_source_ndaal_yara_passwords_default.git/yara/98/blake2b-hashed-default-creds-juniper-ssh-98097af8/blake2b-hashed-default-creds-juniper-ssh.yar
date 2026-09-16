rule blake2b_hashed_default_creds_juniper_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for juniper_ssh."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="585f3b691b374d85d6883348aaad9d63b4cb6b1c9c01aa1ccd2fcb880b27d2e1023c71be0213f161f3caec468178f9266ce06c0517491feb0f181cb4a0c9e67a"
    $a1="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a2="b63fd22eb6fa67b5764bd701c2bca5ecf545e600402cdbcf319859767693d8077bf8513ead89cb0e62dbcb0fe57650cfa948126aef5f039e36863882a4348e6a"
    $a3="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a4="11eaf240b60d40159e0757b56fc4999737b5c9f7eb67ee0cca555c1a46a2cc9b5e7ab62c8513751f968ef466af723bbb39a0ed5ea3bd7693b5de8b8f6745a996"
    $a5="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a6="b63fd22eb6fa67b5764bd701c2bca5ecf545e600402cdbcf319859767693d8077bf8513ead89cb0e62dbcb0fe57650cfa948126aef5f039e36863882a4348e6a"
    $a7="b63fd22eb6fa67b5764bd701c2bca5ecf545e600402cdbcf319859767693d8077bf8513ead89cb0e62dbcb0fe57650cfa948126aef5f039e36863882a4348e6a"
    $a8="b9722577230d64d1f0481b3fc1eb29352f0b3640a967dd9276d8f1b417b2f7dd0dafdfb94cfac7adaeede0e830fcacb427517ae73953dfaa8bceac4ace86b254"
    $a9="b9722577230d64d1f0481b3fc1eb29352f0b3640a967dd9276d8f1b417b2f7dd0dafdfb94cfac7adaeede0e830fcacb427517ae73953dfaa8bceac4ace86b254"
    $a10="8cc249a7d8ec1963c391ae0a8538e62321ba92d9d713ac6eaca8608ed1a25617da77be496ecbfc6773d4000f6cef1dea523118592b45a59f1b50c301e5a89009"
    $a11="8cc249a7d8ec1963c391ae0a8538e62321ba92d9d713ac6eaca8608ed1a25617da77be496ecbfc6773d4000f6cef1dea523118592b45a59f1b50c301e5a89009"
    $a12="ff4339a67d0d9692d46206e9a2ec2054b48e73c0e03b364bcbba76b84560b7df10d8616b3347dcf51ba795ebefef9271cad0f75492b16c8114189593f2d345cf"
    $a13="da8d291e0916119783bb03757c6252fb55ea1d51bfb05e3044d676a827ad9afd002fcfdc5706406cb66b61cea06b9ba64f895d7e66b8aedd5bd84182b9b46fe0"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}