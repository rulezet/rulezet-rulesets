rule j3f7_1bce8cdbc6220b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=j3f7.1bce8cdbc6220b12"
    cluster      = "j3f7.1bce8cdbc6220b12"
    cluster_size = "8"
    filetype     = "text/html"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171122"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "fakejquery redirector html"
    md5_hashes   = "['028cff5b12e46bb4ec76ce0368a6ad71','260bee3f187f57853521213567159af0','e0c3424b81779ef4a0310e02536adf2d']"

  strings:
    $hex_string = "s){for(var x=0,y=metas.length;x<y;x++){if(metas[x].name.toLowerC"

  condition:
    filesize > 4096 and filesize < 16384
    and $hex_string
}