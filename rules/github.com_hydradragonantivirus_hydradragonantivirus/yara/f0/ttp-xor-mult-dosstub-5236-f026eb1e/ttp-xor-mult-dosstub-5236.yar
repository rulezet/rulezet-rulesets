rule TTP_XOR_MULT_DOSStub_5236 {
  strings:
    $key_5236 = { 06 5e [2] 72 46 [2] 35 44 [2] 72 55 [2] 3c 59 [2] 30 53 [2] 27 58 [2] 3c 16 [2] 01 }

  condition:
    any of them
}