rule k3e9_691c5e99c6220b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.691c5e99c6220b12"
    cluster      = "k3e9.691c5e99c6220b12"
    cluster_size = "40"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171111"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "upatre supatre waski"
    md5_hashes   = "['04a97316b601db4254bb760040149d2b','09bc7c615c1bfbb605b8dba14031dd88','ad8fd088533c3f99dfb21af33831c5b8']"

  strings:
    $hex_string = { 00 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f 20 21 22 23 24 25 26 27 28 29 2a 2b 2c 2d 2e 2f 30 31 32 33 34 35 36 37 38 39 3a 3b 3c 3d 3e 3f 40 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}