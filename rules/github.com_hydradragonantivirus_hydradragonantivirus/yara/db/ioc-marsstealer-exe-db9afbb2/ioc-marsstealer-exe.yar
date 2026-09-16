import "hash"
rule IOC_MARSSTEALER_exe {
  meta:
    author     = "Laboratoire Epidemiology & Signal Intelligence"
    ref_IOC    = "IOC_MARSSTEALER_LAB"
    date_IOC   = "2023-11-14 08:40:14"
    info       = "Version 1.0 b"
    internal   = false
    score      = 99
    risk_score = 10
    threat     = "MARSSTEALER"
    file_type  = "exe"
    comment    = "Source : abuse.ch"

  condition:
    hash.sha256(0, filesize) == "487ca2266b9ddac43dde09ad484b1b73ca38071698bfda25d419dcf6c5ed3a22" or
    hash.sha256(0, filesize) == "961fa39e74e92717c34a65cefca250df55cfc76faf1780c45e6b7dfc0fc80eca" or
    hash.sha256(0, filesize) == "b4177d3d69f7951f46d07b01204fc749befc81531720de78ab7e75e93db35c58" or
    hash.sha256(0, filesize) == "349f4ed12f7b4cd5d2cecc282f03ca70a28518094973e66749086920ec47fea4" or
    hash.sha256(0, filesize) == "a79f593a22f2698e351aee60ab23afdaa239ef545297e495df30ecedb99fe222" or
    hash.sha256(0, filesize) == "f94464959b33782231ae5a82624d3407833a812cb17c09bca2647e4476b78fde" or
    hash.sha256(0, filesize) == "e878a8eca5b7f4408bfbd0ccd365f04d4e7d0735a45ea3228ffc322fbb36ee9b" or
    hash.sha256(0, filesize) == "c1463af12fd0e9bda5b5c94381ea22d82abd5d95008ffb77894c5be3c77e3bbc" or
    hash.sha256(0, filesize) == "831abc8d1a70104ae46b5c2c1ce6fce24ef449a03bde0d770a5a67f96ab22e7c"
}