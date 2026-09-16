rule o3e9_2135058cea210912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3e9.2135058cea210912"
    cluster      = "o3e9.2135058cea210912"
    cluster_size = "85"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "weiduan malicious riskware"
    md5_hashes   = "['021a104070c2259e5db9673ddc0abbfd','0377d8474a3a0af766f4f0ce654690ad','3e104f79bd49bc2ff72fe01211908ddc']"

  strings:
    $hex_string = { 3c bb c0 1d 26 e6 78 10 b9 2f 14 3a 88 11 cd 4a 0e 43 54 73 33 7f c6 c5 e1 dc dd 89 86 91 28 38 8e 68 62 72 fd 39 52 1a ce 7d bc 49 1e f7 05 be 82 f9 a7 a6 27 5f 84 bd f1 42 87 1c 58 81 e8 7b }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}