rule TTP_XOR_MULT_DOSStub_7362 {
  strings:
    $key_7362 = { 27 0a [2] 53 12 [2] 14 10 [2] 53 01 [2] 1d 0d [2] 11 07 [2] 06 0c [2] 1d 42 [2] 20 }

  condition:
    any of them
}