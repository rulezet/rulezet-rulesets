rule sha3_384_hashed_default_creds_carel
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for carel."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="90cd7c569836b5b98b3f9cbd011bfcfeda26475b186a648f05a5db70301e2ccd7020caeda91fef10e935dcb0d8c467d4"
    $a1="aac595410801e93eadb099ac575ccc12e43be2c15e31e7991e908329e5beb0729881b3be9ccdb0eeb6eb79335ea38b6d"
    $a2="1872bfb64a427774b1403b959fe4a5727d2f55a728f9926e0ec62c98c465b80caca2bbd7240553d47ab8e40b548c9030"
    $a3="dcaddc1fa1c13b35fb67fc6ec2ac25ece3d28f0462a61f0b503bd5f5b8b9c3df0827166ef1ded08c9bb918d4e180d3bd"
    $a4="134a8b4be353f06e91e075d2dc7ec0f6b5c0c51a0dde9726c4484e2bd09412982d6b140ef79486f7b24d751740163ef6"
    $a5="c617f0628590601e6d5356010496d04be85fef0b4eade714c87a93ff959d242053c0faeea83220e1ae1e635974023299"
    $a6="c9a75c32ba7a7e6e85316a0810fb78b6d093ebe77db18f32c96e64fff6b256b6910f151a8e01da15eb3da92d8855ce41"
    $a7="b30a5277ac3f0bd4bbd555d40c7a80e5b187624a9424179fa8fba824130e5cb197f85da532885f0630fc37f8b73f11a1"
    $a8="251fb475c089348f26e88eadb8e7175f66ae87326c859916a101ce72891465852ed717ab647ca3fd65da298b1e6814ce"
    $a9="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a10="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a11="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a12="f10900ad904232aa227088a65945155469675597b8ba04d7e364caa2edf1213ae3b87bc3ecf9b9cc02773540a42dc56b"
    $a13="764c8195d10386bd9efc2b79d1ae9518492a1efe7a714f1980223249618a85e3bb0af21c1c3052f5e2d996b0895957d6"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}