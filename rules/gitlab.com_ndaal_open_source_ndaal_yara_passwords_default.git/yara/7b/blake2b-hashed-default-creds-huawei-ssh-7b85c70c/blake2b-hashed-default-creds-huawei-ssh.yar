rule blake2b_hashed_default_creds_huawei_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for huawei_ssh."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a1="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a2="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a3="f6baa4e6ca08a6b47ef9c182f4af1301998798bb6c2ef7f410c828838f06e86315e419ffc39e7a2799fd918b33e155e03362f693796cfdc01dd269afc6a8dc4c"
    $a4="e899f7dd47030fb9d0fd800dfde63b23d51ab9e2bd84c8e6535f855a88845d0ca6fb85bdaf12c2aae97befe0cd7a4583660bc55e37c666093d4b84e54e1dad07"
    $a5="e899f7dd47030fb9d0fd800dfde63b23d51ab9e2bd84c8e6535f855a88845d0ca6fb85bdaf12c2aae97befe0cd7a4583660bc55e37c666093d4b84e54e1dad07"
    $a6="9c5dc81d240786e8a743cddc26e3b9e84fa7ad817e2171ec64a9515c789c97220637a2a418428c7c2d19dc47366541c272a04346433d92ec4e72e6c5a0e60ddb"
    $a7="b8c778edba5a254f1a4ca2640d33ffb002db146b6f6898972f61afd134b272496c6bbfbb7781192897ee56aedb5f03fb196c384a2bc35fb7c5513adc26fcbc43"
    $a8="2cfaed14f9fb8fb035262d7b34401f9bea9e865ab47bdef94d1fff4ffaa3abf715ad29fa1cb54730d8326e850169b1977a03711e4481b8e4a0597762d5157a8e"
    $a9="7c4c19165f106d9de2fcb67a6f4d907be2fa7776b1149ff82b69aa74348c0605ea4ef749ce4f5c2ace34cef80a0ce14a480284aa9b6463317b42a11efb64ec38"
    $a10="7c4c19165f106d9de2fcb67a6f4d907be2fa7776b1149ff82b69aa74348c0605ea4ef749ce4f5c2ace34cef80a0ce14a480284aa9b6463317b42a11efb64ec38"
    $a11="7c4c19165f106d9de2fcb67a6f4d907be2fa7776b1149ff82b69aa74348c0605ea4ef749ce4f5c2ace34cef80a0ce14a480284aa9b6463317b42a11efb64ec38"
    $a12="56d4572ef63cfacd97c46028466ef485da6432a81831915c8222f3a55260f06827678d4bfdda1fd3747ba6f782ba9ce9a746de7c223be0a98757fa3e24fea62f"
    $a13="56d4572ef63cfacd97c46028466ef485da6432a81831915c8222f3a55260f06827678d4bfdda1fd3747ba6f782ba9ce9a746de7c223be0a98757fa3e24fea62f"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}