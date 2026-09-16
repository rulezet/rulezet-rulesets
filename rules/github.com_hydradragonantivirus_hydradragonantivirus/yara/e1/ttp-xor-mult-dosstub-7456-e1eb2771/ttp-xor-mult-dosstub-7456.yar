rule TTP_XOR_MULT_DOSStub_7456 {
  strings:
    $key_7456 = { 20 3e [2] 54 26 [2] 13 24 [2] 54 35 [2] 1a 39 [2] 16 33 [2] 01 38 [2] 1a 76 [2] 27 }

  condition:
    any of them
}