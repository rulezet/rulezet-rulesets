rule k3e9_1395b6ab4e400916 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.1395b6ab4e400916"
    cluster      = "k3e9.1395b6ab4e400916"
    cluster_size = "5887"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "ipamor backdoor syzbaukwkdpb"
    md5_hashes   = "['000e7d4785e79fef239601ba634e8dc5','0023c6c05b5adfd824d0f876f98ccb37','00cc504a051c975173b47a4848ef881d']"

  strings:
    $hex_string = { 8d 65 f4 5b 5e 5f 5d c3 89 fb 31 f6 8d 74 26 00 e8 9b 09 ff ff 2b 45 e8 1b 55 ec 39 f2 72 06 77 1e 39 d8 73 1a 89 f9 29 c1 52 8b 45 08 52 51 50 e8 ab 90 fa ff 83 c4 10 83 f8 d9 74 d3 eb c1 b8 }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}