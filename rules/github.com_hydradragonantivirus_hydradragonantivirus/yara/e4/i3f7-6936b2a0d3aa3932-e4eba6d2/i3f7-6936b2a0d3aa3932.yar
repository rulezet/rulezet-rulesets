rule i3f7_6936b2a0d3aa3932 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=i3f7.6936b2a0d3aa3932"
    cluster      = "i3f7.6936b2a0d3aa3932"
    cluster_size = "9"
    filetype     = "text/html"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171122"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "iframe script html"
    md5_hashes   = "['233e2a3bf7b4c5cea58f6e2ac563a7f1','391dd15b48acce7773bdfdc081f65654','ce3775c1f33d162dfc59b19ad3363592']"

  strings:
    $hex_string = "=_blank><img src='//counter.yadro.ru/hit?t21.4;r\"+\r\nescape(docum"

  condition:
    filesize > 1024 and filesize < 4096
    and $hex_string
}