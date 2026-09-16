rule n3f8_396432eb324914e5 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=n3f8.396432eb324914e5"
    cluster         = "n3f8.396432eb324914e5"
    cluster_size    = "38"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180911"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "androidos smforw andr"
    md5_hashes      = "['95913d4ce79e0fe5dbebf04591899d83c8fe056d','4566d2868989ed424d671b0b50fb4810c0e3ff48','d9a6dc25f53db12be4389a788f0220fdeea5ae73']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=n3f8.396432eb324914e5"

  strings:
    $hex_string = { 74 4a 65 6c 6c 79 62 65 61 6e 4d 72 31 2e 6a 61 76 61 00 10 48 43 56 69 65 77 43 6f 6d 70 61 74 49 6d 70 6c 00 12 48 45 42 52 5f 53 43 52 49 50 54 5f 53 55 42 54 41 47 00 04 48 49 44 45 00 17 }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}