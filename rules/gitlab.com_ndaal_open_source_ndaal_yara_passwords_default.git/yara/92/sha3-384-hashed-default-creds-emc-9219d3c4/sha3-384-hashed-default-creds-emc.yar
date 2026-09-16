rule sha3_384_hashed_default_creds_emc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for emc."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4d58bfd306307b517f58bda7326e3570b9e38ca9cff807e9023d8c3af94c89c0cb1c5216038bc235e8ff6fcfb86fcf6c"
    $a1="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a2="e5056f348fbae4dce2fdcd72782a040f7cb96d4182e56470d86de8b0297d1a99ef6e9f22187f01a164e75789a902c5cb"
    $a3="9f6e3a5a86ab5e0fc8d721d32028c610a3555b077f3a2d6f48c36a6a7d811f25eb3a1849b202a5ec93bffe57533f415d"
    $a4="390370553b9701729502c071325707136e00c66254354810413142cf4e1b53dd4012a41a46941fbde20b0c2fee632164"
    $a5="39954ed9bbe8f2430596f56c7d9e1e2608ff3b5a72137ee5b13de5152151627b7cd7984c86ebaa3c7cf6413d31be4c28"
    $a6="4d58bfd306307b517f58bda7326e3570b9e38ca9cff807e9023d8c3af94c89c0cb1c5216038bc235e8ff6fcfb86fcf6c"
    $a7="3832258cfd38ddad07cbac3e2096570fe0d62f3ef422de0ac24bb04d0a0b375ad5a55e5d14055ebe28e92f4901dd36f3"
    $a8="658e9dfde4ebf1355126c0372b5dcd9ef83307c49bff1423bcee8fa7cfd74e09b6cd09f00bbcfe459b12c47a44a2a02e"
    $a9="918a2fc933aa7b47d43ee85682d32d29601d256aa0f768a9c974dd5db9c8c5df5d3a78602e51ab8c3f409690f910e316"
    $a10="d388910b9edeb37357b801ba430b5675e84e47dd07f49731b7efdc7f77c8ae88e7c3f28f1a7a7e0eb9c37a9e445e81db"
    $a11="ee27bf37b19416948601ece82354a16f45261823dc67fa50572c26307a9461c324db70d31cfa6d9224831d0166669529"
    $a12="10fb06fe1d152dce31277d56a48e2ea545df7c655f6d4028c31931586060a09db3e16151c673ddec2fd3cfae8b8ff0c3"
    $a13="aac595410801e93eadb099ac575ccc12e43be2c15e31e7991e908329e5beb0729881b3be9ccdb0eeb6eb79335ea38b6d"
    $a14="4d58bfd306307b517f58bda7326e3570b9e38ca9cff807e9023d8c3af94c89c0cb1c5216038bc235e8ff6fcfb86fcf6c"
    $a15="aac595410801e93eadb099ac575ccc12e43be2c15e31e7991e908329e5beb0729881b3be9ccdb0eeb6eb79335ea38b6d"
    $a16="8c2660f01503a611da0e444a97e9c17b026a56396ce2dd4bd646ac0cc5f4c0b2dfb39c6746c306b777cb5eabd3c02449"
    $a17="273e59ebf559e1e5b94c785777a7edfd4b4f8b09e11b8db7f24b94e84acb7e48ef120e234c21ef9d319e41c9188e5c83"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}