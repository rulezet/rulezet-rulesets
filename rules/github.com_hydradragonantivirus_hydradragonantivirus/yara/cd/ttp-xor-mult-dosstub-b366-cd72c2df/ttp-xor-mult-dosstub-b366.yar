rule TTP_XOR_MULT_DOSStub_b366 {
  strings:
    $key_b366 = { e7 0e [2] 93 16 [2] d4 14 [2] 93 05 [2] dd 09 [2] d1 03 [2] c6 08 [2] dd 46 [2] e0 }

  condition:
    any of them
}