rule TTP_XOR_MULT_DOSStub_abcf {
  strings:
    $key_abcf = { ff a7 [2] 8b bf [2] cc bd [2] 8b ac [2] c5 a0 [2] c9 aa [2] de a1 [2] c5 ef [2] f8 }

  condition:
    any of them
}