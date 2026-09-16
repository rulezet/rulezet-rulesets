rule k3e9_329b97a1c2000b16 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.329b97a1c2000b16"
    cluster      = "k3e9.329b97a1c2000b16"
    cluster_size = "8"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171118"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "chir runouce emailworm"
    md5_hashes   = "['129584dada47ee2ef2548acbb67fd780','1526197591df0a6ed6870fb42031be56','fe9678561032eaf3fd4f1ad72957a80a']"

  strings:
    $hex_string = { 6e f9 43 86 44 08 59 8f 5a 74 d9 04 ad de 25 ac 1e 11 49 9e 3a ad 0a 4a b5 60 fd ed 0d f1 fe 5e 35 06 4e 93 81 9b 24 d7 f7 cc 88 e4 16 63 f4 1b fb eb 46 ae df 95 20 bf bb 91 6a 15 7d 03 8a 57 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}