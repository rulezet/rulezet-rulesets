rule TTP_XOR_MULT_DOSStub_730a {
  strings:
    $key_730a = { 27 62 [2] 53 7a [2] 14 78 [2] 53 69 [2] 1d 65 [2] 11 6f [2] 06 64 [2] 1d 2a [2] 20 }

  condition:
    any of them
}