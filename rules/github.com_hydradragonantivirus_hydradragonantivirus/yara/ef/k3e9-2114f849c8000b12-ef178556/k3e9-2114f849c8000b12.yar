rule k3e9_2114f849c8000b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.2114f849c8000b12"
    cluster      = "k3e9.2114f849c8000b12"
    cluster_size = "586"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "jaik backdoor darkkomet"
    md5_hashes   = "['000e9dda9f00082c800a7a2f26527cb0','00b8fa86ca880ffee0c576adcc5e4737','07cae0f09ab0f45433f1b4376f0526df']"

  strings:
    $hex_string = "OS Id=\"{1f676c76-80e1-4239-95bb-83d0f6d0da78}\"></supportedOS>\r\n "

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}