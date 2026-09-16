import "hash"
rule IOC_RECORDBREAKER_exe {
  meta:
    author     = "Laboratoire Epidemiology & Signal Intelligence"
    ref_IOC    = "IOC_RECORDBREAKER_LAB"
    date_IOC   = "2023-11-14 10:05:08"
    info       = "Version 1.0 b"
    internal   = false
    score      = 99
    risk_score = 10
    threat     = "RECORDBREAKER"
    file_type  = "exe"
    comment    = "Source : abuse.ch"

  condition:
    hash.sha256(0, filesize) == "9b6a1d1a00ddd716e344cc64e5592291bb2eb2f5d36a95a32a7b2bddd02a1402" or
    hash.sha256(0, filesize) == "c3ca3799150177eddce80d6eaf8905f29b02c31651f565a913690b83ba36a788" or
    hash.sha256(0, filesize) == "1abb8e978cc50ac436946ba779cfc8bdd5022a6251aca2d761b09b5a6433fbee" or
    hash.sha256(0, filesize) == "114e74be49ed1e1bc90c85a74aaf60fbc8d766d0e8755c100ffab51a43d71404" or
    hash.sha256(0, filesize) == "831abc8d1a70104ae46b5c2c1ce6fce24ef449a03bde0d770a5a67f96ab22e7c"
}