rule blake2b_hashed_default_creds_asante
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for asante."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a4c817340369b1c68cb9f4e9650ac0f85c10f5bcb1a1ef79411a4be0cd2e6d025a44c09d7df130cd673d276cca8dac9a7114c7132c79a70fcf4255a029e988eb"
    $a1="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a2="a4c817340369b1c68cb9f4e9650ac0f85c10f5bcb1a1ef79411a4be0cd2e6d025a44c09d7df130cd673d276cca8dac9a7114c7132c79a70fcf4255a029e988eb"
    $a3="da283ad64aaa8dade96b1a71e19d9bb0a59d346dae1fafd0a41aa452fa9471372b2fed29d75429f0aab977aaf01215700f166867879afc88565bc0bfc81b8229"
    $a4="a0b27c918d9f592294404e94211de06da421cee7b40ab4fb19cdfb7709ba4fc1f1dd5b141ebbf3c3289e39ef4c64ef0e16e670e32ea58fc9b5e42ce43867f886"
    $a5="5aab9d8b71180f3a0418c2b3b244fc89b6e0da50f22ec18f96e31ab97a55bf76daca60d374f7de9caf7954d8d054c092bd6a718cd0db1b915c48aa93e97a42c9"
    $a6="a0b27c918d9f592294404e94211de06da421cee7b40ab4fb19cdfb7709ba4fc1f1dd5b141ebbf3c3289e39ef4c64ef0e16e670e32ea58fc9b5e42ce43867f886"
    $a7="54f187577cc51bf3fc27e69d10d8b2b919014945cb21a69ec4efca5b40b6b0daf5f2c94a409b5500aa1508159a3b35e2584ef0172fd568de43952c7030e2ba87"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}