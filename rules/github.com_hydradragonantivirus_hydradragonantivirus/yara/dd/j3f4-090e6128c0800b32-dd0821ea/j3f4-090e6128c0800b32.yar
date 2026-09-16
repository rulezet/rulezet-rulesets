rule j3f4_090e6128c0800b32 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=j3f4.090e6128c0800b32"
    cluster      = "j3f4.090e6128c0800b32"
    cluster_size = "104"
    filetype     = "PE32 executable (GUI) Intel 80386 Mono/.Net assembly"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171122"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "razy agbf malicious"
    md5_hashes   = "['006a50cb2766485b04252fcd6536bb0b','02e80f85fa13ac11516f245348845d77','1fbffdc6ffd6961b6a2392c1057d4417']"

  strings:
    $hex_string = { 00 00 00 00 00 00 00 00 00 00 00 00 88 e3 f2 ff b4 f7 fb ff b0 f5 f9 ff aa f1 f7 ff e8 fa fc ff 56 bd d4 ff 68 b9 cd ff 70 c9 e0 ff 90 e2 f0 ff 89 de ee ff 82 da ec ff 6f cc e2 ff 68 c6 dd 96 }

  condition:
    filesize > 4096 and filesize < 16384
    and $hex_string
}