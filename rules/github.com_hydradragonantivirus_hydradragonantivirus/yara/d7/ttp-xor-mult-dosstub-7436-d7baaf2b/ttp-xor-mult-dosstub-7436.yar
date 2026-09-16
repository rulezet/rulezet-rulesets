rule TTP_XOR_MULT_DOSStub_7436 {
  strings:
    $key_7436 = { 20 5e [2] 54 46 [2] 13 44 [2] 54 55 [2] 1a 59 [2] 16 53 [2] 01 58 [2] 1a 16 [2] 27 }

  condition:
    any of them
}