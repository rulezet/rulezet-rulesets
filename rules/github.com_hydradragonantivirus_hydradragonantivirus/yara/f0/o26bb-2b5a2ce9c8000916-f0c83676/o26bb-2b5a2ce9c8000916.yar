rule o26bb_2b5a2ce9c8000916 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=o26bb.2b5a2ce9c8000916"
    cluster         = "o26bb.2b5a2ce9c8000916"
    cluster_size    = "207"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "ursu filetour dangerousobject"
    md5_hashes      = "['192fa4f791ac35726a1adf2916ebf318dbbb219d','89901f7b3f3cf85f9d804e88c1d0bfa2a2126afd','11f47e15d4f3f9c71b9cef87f024129f8f857e88']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=o26bb.2b5a2ce9c8000916"

  strings:
    $hex_string = { 7b 7b b7 ff 01 01 66 ff 02 02 64 ff 10 0e 42 ff 34 30 28 ff 32 2e 2a ff 31 2d 29 ff 32 2f 2b ff 6d 61 5c ff 8e 7e 78 ff 8a 7b 75 ff 89 7a 74 ff 86 77 71 ff 85 76 70 ff 7c 6f 69 c8 00 00 00 1c }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}