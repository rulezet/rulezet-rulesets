import "hash"
rule IOC_REMCOSRAT_zip {
  meta:
    author     = "Laboratoire Epidemiology & Signal Intelligence"
    ref_IOC    = "IOC_REMCOSRAT_LAB"
    date_IOC   = "2023-11-14 11:57:52"
    info       = "Version 1.0 b"
    internal   = false
    score      = 99
    risk_score = 10
    threat     = "REMCOSRAT"
    file_type  = "zip"
    comment    = "Source : abuse.ch"

  condition:
    hash.sha256(0, filesize) == "12b615a29aa38f8084b6e23828007897953c887037a8ebea8828c62cfb396831" or
    hash.sha256(0, filesize) == "392624a0ee0d3c34ae9ad9607e9f8683156447379beac0ec8519c70dedbb74d0" or
    hash.sha256(0, filesize) == "831abc8d1a70104ae46b5c2c1ce6fce24ef449a03bde0d770a5a67f96ab22e7c"
}