rule o3e7_33335e86ca210b32 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3e7.33335e86ca210b32"
    cluster      = "o3e7.33335e86ca210b32"
    cluster_size = "16"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171122"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "installmonstr malicious dlboost"
    md5_hashes   = "['1452c169e9bd577b6fd7197bffaed3d7','a4c594292ce97accce6daf51cc244ddc','a4c594292ce97accce6daf51cc244ddc']"

  strings:
    $hex_string = { 00 61 62 63 64 65 66 67 68 69 6a 6b 6c 6d 6e 6f 70 71 72 73 74 75 76 77 78 79 7a 41 42 43 44 45 46 47 48 49 4a 4b 4c 4d 4e 4f 50 51 52 53 54 55 56 57 58 59 5a 31 32 33 34 35 36 37 38 39 30 2d }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}