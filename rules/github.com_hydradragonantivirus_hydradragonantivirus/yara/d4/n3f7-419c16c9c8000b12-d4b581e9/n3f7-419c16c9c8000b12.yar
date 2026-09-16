rule n3f7_419c16c9c8000b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=n3f7.419c16c9c8000b12"
    cluster      = "n3f7.419c16c9c8000b12"
    cluster_size = "140"
    filetype     = ""
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171122"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "ramnit script html"
    md5_hashes   = "['068daa1d7ea9157cac9a5c8ce94baa90','082f09671df7b9e1ef8e02c99e011585','1e0e130ec18ac88f5954a90521ad39f6']"

  strings:
    $hex_string = "hr(CLng(\"&H\" & Mid(WriteData,i,2)))\r\nNext\r\nFileObj.Close\r\nEnd If"

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}