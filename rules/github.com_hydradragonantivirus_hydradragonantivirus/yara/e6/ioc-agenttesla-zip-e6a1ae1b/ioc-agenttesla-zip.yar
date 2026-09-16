import "hash"
rule IOC_AGENTTESLA_zip {
  meta:
    author     = "Laboratoire Epidemiology & Signal Intelligence"
    ref_IOC    = "IOC_AGENTTESLA_LAB"
    date_IOC   = "2023-11-14 08:46:46"
    info       = "Version 1.0 b"
    internal   = false
    score      = 99
    risk_score = 10
    threat     = "AGENTTESLA"
    file_type  = "zip"
    comment    = "Source : abuse.ch"

  condition:
    hash.sha256(0, filesize) == "5841001fb1a91673e31a012d599cbad0e47c93c37beba3426e7fda17dcca5cd4" or
    hash.sha256(0, filesize) == "8dc7626964bb2236228f1cd54d064c5a03deeecb0fd4cd64ee010e36bb046d23" or
    hash.sha256(0, filesize) == "b05c4c012a23a232bb4cb07b15af09c7df8ff87cd664f6169bf2b9cf0ec392d3" or
    hash.sha256(0, filesize) == "0598d24987b6a7a5421e7e34589b81a5f2ff9e8e1f176569d0f4d33783e93f57" or
    hash.sha256(0, filesize) == "ceb734f8c9859a740dc419596343529552f55f8956790a001b33850ca5150c35" or
    hash.sha256(0, filesize) == "51024442ed796e4de733bbbc83457b1cc193ab447e428a2a58972ce338864b6a" or
    hash.sha256(0, filesize) == "2d0c195cad42c20024600cfa6643a66c7dfe17ec96cc5f36bddb3b48f53ba0ea" or
    hash.sha256(0, filesize) == "6767b678fcd5cf5e973501473e540fe5c1c716101b952071f075d9ba0402be77" or
    hash.sha256(0, filesize) == "831abc8d1a70104ae46b5c2c1ce6fce24ef449a03bde0d770a5a67f96ab22e7c"
}