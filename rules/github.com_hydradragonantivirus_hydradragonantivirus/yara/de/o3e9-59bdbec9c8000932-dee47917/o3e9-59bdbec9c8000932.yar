rule o3e9_59bdbec9c8000932 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3e9.59bdbec9c8000932"
    cluster      = "o3e9.59bdbec9c8000932"
    cluster_size = "4"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171123"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "virlock symmi nabucur"
    md5_hashes   = "['b0689b65adc9fa4797555cc00c09731d','b23e92fa4c8ac363e5c5028974ae4e71','f033b5db8d928b9703068031d9c35e79']"

  strings:
    $hex_string = { eb f2 f9 00 dd e6 ee 00 ae ba c3 00 c3 cb d5 00 c4 cf d7 00 ba c5 d3 00 7b 82 95 00 b8 c1 cc 00 9d b2 d2 00 40 52 72 00 36 4a 4f 00 57 90 2b 00 5d 9c 2a 00 66 af 2d 00 6a b1 2e 00 6d b3 33 00 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}