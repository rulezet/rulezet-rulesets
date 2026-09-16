rule TTP_XOR_MULT_DOSStub_7376 {
  strings:
    $key_7376 = { 27 1e [2] 53 06 [2] 14 04 [2] 53 15 [2] 1d 19 [2] 11 13 [2] 06 18 [2] 1d 56 [2] 20 }

  condition:
    any of them
}