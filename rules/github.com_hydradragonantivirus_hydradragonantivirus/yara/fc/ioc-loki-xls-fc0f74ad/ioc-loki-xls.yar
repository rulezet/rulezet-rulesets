import "hash"
rule IOC_LOKI_xls {
  meta:
    author     = "Laboratoire Epidemiology & Signal Intelligence"
    ref_IOC    = "IOC_LOKI_LAB"
    date_IOC   = "2023-11-14 06:53:30"
    info       = "Version 1.0 b"
    internal   = false
    score      = 99
    risk_score = 10
    threat     = "LOKI"
    file_type  = "xls"
    comment    = "Source : abuse.ch"

  condition:
    hash.sha256(0, filesize) == "174489d70aa181c2994b063518b349b1b23eabd988f192b37ea3112241d93f44" or
    hash.sha256(0, filesize) == "542e4e849b04fa8953a08ecb6ddd300120855e69c9f5df0975ddf1935eacf408" or
    hash.sha256(0, filesize) == "831abc8d1a70104ae46b5c2c1ce6fce24ef449a03bde0d770a5a67f96ab22e7c"
}