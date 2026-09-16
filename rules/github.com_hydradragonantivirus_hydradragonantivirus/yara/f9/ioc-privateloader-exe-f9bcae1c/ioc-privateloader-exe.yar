import "hash"
rule IOC_PRIVATELOADER_exe {
  meta:
    author     = "Laboratoire Epidemiology & Signal Intelligence"
    ref_IOC    = "IOC_PRIVATELOADER_LAB"
    date_IOC   = "2023-11-14 08:19:34"
    info       = "Version 1.0 b"
    internal   = false
    score      = 99
    risk_score = 10
    threat     = "PRIVATELOADER"
    file_type  = "exe"
    comment    = "Source : abuse.ch"

  condition:
    hash.sha256(0, filesize) == "2cb5b2678054dd2f1b93d37a96b927830c4a7da699f061adee370807088257de" or
    hash.sha256(0, filesize) == "38981ca59bd6187df55f92af67932a165b44a30587be906232e42f87c160d523" or
    hash.sha256(0, filesize) == "831abc8d1a70104ae46b5c2c1ce6fce24ef449a03bde0d770a5a67f96ab22e7c"
}