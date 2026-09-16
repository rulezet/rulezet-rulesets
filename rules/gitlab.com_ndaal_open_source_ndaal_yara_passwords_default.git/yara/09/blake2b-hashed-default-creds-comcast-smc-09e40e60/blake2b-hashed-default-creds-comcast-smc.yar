rule blake2b_hashed_default_creds_comcast_smc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for comcast_smc."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3d94aefd59330b06708147e027d556f6edcf975da2cca1ff3ee0d1a77c5cacaa8a78c8abca0ba6167d2695b75e272552803bc582193bca3592f54946c16e9f39"
    $a1="4821d6006e6c5f0f1243f7902de4755604f519f7f623f16df1453cbf451bc57ab06e832a494cd5a4e3fc9a228b1cf3f1db63afb97b26468424baa268ce0fafd0"
    $a2="69baf6e415c26242d39904368c39f644eeb36eab71912c8aff38911aabab0ddc03317e9c93d209a8306a8789a51a6b90abd5e04a4454de5afdedc95314ff45c9"
    $a3="4821d6006e6c5f0f1243f7902de4755604f519f7f623f16df1453cbf451bc57ab06e832a494cd5a4e3fc9a228b1cf3f1db63afb97b26468424baa268ce0fafd0"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}