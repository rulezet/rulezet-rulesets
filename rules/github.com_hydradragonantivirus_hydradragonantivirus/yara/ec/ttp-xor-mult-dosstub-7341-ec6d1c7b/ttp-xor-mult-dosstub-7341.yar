rule TTP_XOR_MULT_DOSStub_7341 {
  strings:
    $key_7341 = { 27 29 [2] 53 31 [2] 14 33 [2] 53 22 [2] 1d 2e [2] 11 24 [2] 06 2f [2] 1d 61 [2] 20 }

  condition:
    any of them
}