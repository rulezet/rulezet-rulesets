rule p3f0_4b24ea48c0000916 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=p3f0.4b24ea48c0000916"
    cluster      = "p3f0.4b24ea48c0000916"
    cluster_size = "140"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "ursu gamemodding heuristic"
    md5_hashes   = "['0258b11311ab113e7177edbc70ba3fd2','028f9193eec427bbb640387058b28c08','2846acdecb0b06fff2e66f9f991fc1e8']"

  strings:
    $hex_string = { d1 0d d3 65 b7 48 7f 33 31 e5 b5 b9 02 7d f0 e6 03 f4 86 83 16 cd 9b f3 72 9e ed 0c b0 6a 4b b6 69 8b 32 ab fa 0e e8 a2 be 59 14 f6 f2 15 87 38 27 ae 53 24 93 ea 0b f1 6c db 01 8a 68 5e 88 67 }

  condition:
    filesize > 4194304 and filesize < 16777216
    and $hex_string
}