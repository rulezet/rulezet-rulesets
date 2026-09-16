rule TTP_XOR_MULT_DOSStub_73f6 {
  strings:
    $key_73f6 = { 27 9e [2] 53 86 [2] 14 84 [2] 53 95 [2] 1d 99 [2] 11 93 [2] 06 98 [2] 1d d6 [2] 20 }

  condition:
    any of them
}