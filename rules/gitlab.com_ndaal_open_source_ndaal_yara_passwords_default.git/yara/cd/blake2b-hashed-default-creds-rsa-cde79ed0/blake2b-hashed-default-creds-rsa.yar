rule blake2b_hashed_default_creds_rsa
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for rsa."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c4717d406b24c889867a4216e46c6cb553d9fb1daa43180b306813ef5d552677554953f92e2711668757433fc1976ba9c8e66b0c6d375b40fb605e72edd835b0"
    $a1="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a2="6900131c6ab65f150a110925593c6ef5e27bea2d2f7c5ab20ec61b84fbe06aef54173c0041c5cd9e9dc611498d84b6f989ba352785fd0683f0b9c2dd95712ec4"
    $a3="20ab24778b723106269c870575c7463ee0ca0d8a6e1e338ad1dc4ff7a89606f7375e04ae4c768892d48991c7b8d2e6720fb39edb86a772e3e7adf723cc8fcb39"
    $a4="d1c53092b65f84d48a68097a674b548b6bb67ac4144b3e1e459a6506e721a52b6fba53cd6908564bb56dec4e7349e6d1c3c6cb781201257d23796ba5551c9d7e"
    $a5="33ace3eb11c517be804f516ab407838b51c6eb5baff3203ce3a320b6750bd1bcbf7091092555a332abc4d467ef3c13fcd9ff5312aa0036b98ff1b29774d55f4a"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}