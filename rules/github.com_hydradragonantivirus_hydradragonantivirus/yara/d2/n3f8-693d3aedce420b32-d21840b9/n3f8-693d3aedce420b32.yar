rule n3f8_693d3aedce420b32 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=n3f8.693d3aedce420b32"
    cluster         = "n3f8.693d3aedce420b32"
    cluster_size    = "16"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180911"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "droidkungfu androidos kungfu"
    md5_hashes      = "['58b2c3273a6307a84e2b728f5731258e6e91ed17','285f1fb94f34f3b03221269d18245a04ed2a7f94','192ebaa9ff235dac74b61c28dc91c1d7031306bf']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=n3f8.693d3aedce420b32"

  strings:
    $hex_string = { 00 40 30 31 32 33 34 35 36 37 38 39 61 62 63 64 65 66 67 68 69 6a 6b 6c 6d 6e 6f 70 71 72 73 74 75 76 77 78 79 7a 41 42 43 44 45 46 47 48 49 4a 4b 4c 4d 4e 4f 50 51 52 53 54 55 56 57 58 59 5a }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}