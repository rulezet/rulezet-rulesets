rule k3e9_1b1c6898b3e10b16 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.1b1c6898b3e10b16"
    cluster      = "k3e9.1b1c6898b3e10b16"
    cluster_size = "32040"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171122"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "neshta hllp malicious"
    md5_hashes   = "['000417f5bc8b994dc4423ba1a7add8da','0005ff25d2e1d9b9d3a556f075ffc6e1','001f081ba31b965872872517b207d713']"

  strings:
    $hex_string = { 31 2e 30 20 4d 61 64 65 20 69 6e 20 42 65 6c 61 72 75 73 2e 20 cf f0 fb e2 69 f2 e0 ed ed e5 20 f3 f1 69 ec 20 7e f6 69 ea e0 e2 fb ec 7e 20 e1 e5 eb e0 f0 f3 f1 5f ea 69 ec 20 e4 e7 ff f3 f7 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}