import "hash"
rule IOC_COINMINER_elf {
  meta:
    author     = "Laboratoire Epidemiology & Signal Intelligence"
    ref_IOC    = "IOC_COINMINER_LAB"
    date_IOC   = "2023-11-15 09:24:49"
    info       = "Version 1.0 b"
    internal   = false
    score      = 99
    risk_score = 10
    threat     = "COINMINER"
    file_type  = "elf"
    comment    = "Source : abuse.ch"

  condition:
    hash.sha256(0, filesize) == "199c01b177aa7c4bb01dae876012c696e4e30aada4cf1c7edf7936eee0d7876e" or
    hash.sha256(0, filesize) == "5082ed106ffd1f4f71e016e49b88c0e61d3ffd00f7860ebc4fa1406735cd84da" or
    hash.sha256(0, filesize) == "151df3364d6d3ff361ed45ea944386ad8b45fc8327929447de5f7a86bc19547b" or
    hash.sha256(0, filesize) == "0233e973071b55934eeafc66da12e02587c5b1604d3b300ccbc44f018c2b80cf" or
    hash.sha256(0, filesize) == "831abc8d1a70104ae46b5c2c1ce6fce24ef449a03bde0d770a5a67f96ab22e7c"
}