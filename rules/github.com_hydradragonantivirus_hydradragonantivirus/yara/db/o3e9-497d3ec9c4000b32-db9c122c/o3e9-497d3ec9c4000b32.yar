rule o3e9_497d3ec9c4000b32 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3e9.497d3ec9c4000b32"
    cluster      = "o3e9.497d3ec9c4000b32"
    cluster_size = "3"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171123"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "virlock yjbhxcei cryptor"
    md5_hashes   = "['a31121259cecad8111c0e51143c85d36','cd31fddd6e5ed3f57b06190592f834c3','d4c4976334b74707c86cb5c4fb31f874']"

  strings:
    $hex_string = { 1c 3d d0 ff 21 49 db ff 27 54 e5 ff 2a 5c ed ff 2b 5d ee ff 28 56 e8 ff 23 4c de ff 1d 40 d3 ff 7b 63 86 ff fe e3 c8 ff fc d1 be ff dd 97 8b ff 33 1a 0d 8c 35 1b 0e 3c 3f 1b 1b 0e 7f 7f 7f 01 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}