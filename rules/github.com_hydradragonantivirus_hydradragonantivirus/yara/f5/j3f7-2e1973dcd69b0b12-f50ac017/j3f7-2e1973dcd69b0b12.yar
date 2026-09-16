rule j3f7_2e1973dcd69b0b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=j3f7.2e1973dcd69b0b12"
    cluster      = "j3f7.2e1973dcd69b0b12"
    cluster_size = "10"
    filetype     = "text/html"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171122"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "redirector fakejquery script"
    md5_hashes   = "['1931cd2a6d863613cf13df79e8c4089b','2d85da6475bce65d419aa722e32503f0','fd158836d745c8c81879b70beefebac5']"

  strings:
    $hex_string = "aURL(),c!==d);case\"diversity\":return i.fillText(j(55356,57221),0"

  condition:
    filesize > 4096 and filesize < 16384
    and $hex_string
}