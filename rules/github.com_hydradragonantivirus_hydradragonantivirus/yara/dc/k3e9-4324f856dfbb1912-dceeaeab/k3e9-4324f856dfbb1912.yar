rule k3e9_4324f856dfbb1912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.4324f856dfbb1912"
    cluster      = "k3e9.4324f856dfbb1912"
    cluster_size = "10"
    filetype     = ""
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171122"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "virut virtob virux"
    md5_hashes   = "['4e1bd72c1d89130b6e196104e35844ba','ac4c41463a8d9d5f35db1a594e1f36e6','e640bc376e842ab56e5fba3895667548']"

  strings:
    $hex_string = { e0 8a 06 3a c3 74 04 3c 20 76 f2 89 5d ac 8d 45 80 50 ff 15 7c 10 00 01 f6 45 ac 01 74 11 0f b7 45 b0 eb 0e 80 3e 20 76 d8 46 89 75 e0 eb f5 6a 0a 58 50 56 53 53 ff d7 50 e8 43 ea ff ff 8b f0 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}