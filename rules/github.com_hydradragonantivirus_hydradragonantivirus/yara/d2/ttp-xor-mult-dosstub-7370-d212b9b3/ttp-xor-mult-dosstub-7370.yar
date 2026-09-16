rule TTP_XOR_MULT_DOSStub_7370 {
  strings:
    $key_7370 = { 27 18 [2] 53 00 [2] 14 02 [2] 53 13 [2] 1d 1f [2] 11 15 [2] 06 1e [2] 1d 50 [2] 20 }

  condition:
    any of them
}