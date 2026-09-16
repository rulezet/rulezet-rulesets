rule k3e9_4324d85699bb1912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.4324d85699bb1912"
    cluster      = "k3e9.4324d85699bb1912"
    cluster_size = "47"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171122"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "virut virtob virux"
    md5_hashes   = "['0db0a2af126fc4e26a577f78772d3250','0fd4f642e9f55e51f3f53bbe428716ff','b3046cb2ef58b8ae9538447509acc437']"

  strings:
    $hex_string = { f7 de 1b f6 46 83 7d f8 00 74 09 ff 75 f8 ff 15 0c 10 00 01 8b c6 eb 02 33 c0 5f 5e 5b c9 c2 04 00 cc cc cc cc cc 8b ff 55 8b ec 81 ec 1c 02 00 00 a1 f0 60 00 01 53 8b 5d 08 57 89 45 fc 8d 85 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}