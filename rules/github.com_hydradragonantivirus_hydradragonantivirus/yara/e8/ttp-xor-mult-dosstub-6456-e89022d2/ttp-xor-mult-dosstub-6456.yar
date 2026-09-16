rule TTP_XOR_MULT_DOSStub_6456 {
  strings:
    $key_6456 = { 30 3e [2] 44 26 [2] 03 24 [2] 44 35 [2] 0a 39 [2] 06 33 [2] 11 38 [2] 0a 76 [2] 37 }

  condition:
    any of them
}