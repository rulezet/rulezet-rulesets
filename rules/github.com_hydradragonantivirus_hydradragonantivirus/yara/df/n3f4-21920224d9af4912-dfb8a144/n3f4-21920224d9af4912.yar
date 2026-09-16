rule n3f4_21920224d9af4912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=n3f4.21920224d9af4912"
    cluster      = "n3f4.21920224d9af4912"
    cluster_size = "3"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171111"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "malicious heuristic kryptik"
    md5_hashes   = "['a28d6ed310d8039147d266798bf83b81','c6da7b84881de94a2a35bc791fb65d4f','db964d3d4a463a2c359c359e4986ca1d']"

  strings:
    $hex_string = "Uom68Ga0ojzAeFYGTy+BXOADMOMtWkjNQ9i/1I8cM02TvgwRVHpjS3KkEn75FrzL"

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}