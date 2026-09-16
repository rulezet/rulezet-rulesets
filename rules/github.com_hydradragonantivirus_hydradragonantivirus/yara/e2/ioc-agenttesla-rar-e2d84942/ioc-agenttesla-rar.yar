import "hash"
rule IOC_AGENTTESLA_rar {
  meta:
    author     = "Laboratoire Epidemiology & Signal Intelligence"
    ref_IOC    = "IOC_AGENTTESLA_LAB"
    date_IOC   = "2023-11-14 08:16:01"
    info       = "Version 1.0 b"
    internal   = false
    score      = 99
    risk_score = 10
    threat     = "AGENTTESLA"
    file_type  = "rar"
    comment    = "Source : abuse.ch"

  condition:
    hash.sha256(0, filesize) == "cc9ceb589bbbf22fee3f7456b0269d06773a6e96974aa20936868bcbbce88ba6" or
    hash.sha256(0, filesize) == "ff28a45905e0bb9d9af43c5e4d8e8fa27248880cb7a24d2bd7c16d5ddcdb8caf" or
    hash.sha256(0, filesize) == "4bc3218865e598320faef41090da4ab23101fff8531ffebcaf6523a0217ea898" or
    hash.sha256(0, filesize) == "6f005ba0b96e1110d036613975314ef0827afae187ac93384770ea57c3103c26" or
    hash.sha256(0, filesize) == "2c1ac1fdee3753349c582a5a518c301baee1144d0ab52827792919dcf3e4c7cd" or
    hash.sha256(0, filesize) == "1bc363ba8df6cc044fe7eea73aab1ec7276ee28afa716b19e5681335189aa070" or
    hash.sha256(0, filesize) == "ad654aeceeb0af81e68181bb70bfe413527895eb4b23b378bb084129f9ae1a0c" or
    hash.sha256(0, filesize) == "861f1511b4464e0c3fd64db843fe357894204b1427014232c6c7434b02947811" or
    hash.sha256(0, filesize) == "831abc8d1a70104ae46b5c2c1ce6fce24ef449a03bde0d770a5a67f96ab22e7c"
}