import "hash"
rule IOC_LUMMASTEALER_exe {
  meta:
    author     = "Laboratoire Epidemiology & Signal Intelligence"
    ref_IOC    = "IOC_LUMMASTEALER_LAB"
    date_IOC   = "2023-11-14 09:55:08"
    info       = "Version 1.0 b"
    internal   = false
    score      = 99
    risk_score = 10
    threat     = "LUMMASTEALER"
    file_type  = "exe"
    comment    = "Source : abuse.ch"

  condition:
    hash.sha256(0, filesize) == "eb2a0541c88a8d839a3506d67260951e8f6bcf4e46741658cb69c7178da93634" or
    hash.sha256(0, filesize) == "56f2f2548297d7b72af40b7898d1dabe2dcb8090388985b218f4452d1a9c6ebf" or
    hash.sha256(0, filesize) == "2d43530c81da22814e9debab6cc5dc8583d87b50c374e84c4ef153b0e51e4430" or
    hash.sha256(0, filesize) == "c309b4f0f99e1686e9bc954da81701b3fd26cfccd17627cde55df929fb712311" or
    hash.sha256(0, filesize) == "48e0956022211b6dde5b2f63169f3b1330bd010f61b19435faa54ad183709a48" or
    hash.sha256(0, filesize) == "5911b3af7d48ce74fc6644064f176990a34230786598cfd97b90cf5208be7f5d" or
    hash.sha256(0, filesize) == "371178f2c72748b41e33d1862f900e09d955f884f4b59857073c409e61b254ce" or
    hash.sha256(0, filesize) == "4567eee3f0b37c6ce2e213d54820f1fcc2093f97743354bff6f98c57456c182f" or
    hash.sha256(0, filesize) == "970dd198cf22fd0add061581be379fac2403bc071ebd495d32050e0c7ce5d75e" or
    hash.sha256(0, filesize) == "4d201919a0ebca66c9444a66f9324fb870e4af25252f27aa405255cca0167379" or
    hash.sha256(0, filesize) == "831abc8d1a70104ae46b5c2c1ce6fce24ef449a03bde0d770a5a67f96ab22e7c"
}