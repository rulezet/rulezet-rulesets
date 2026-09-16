rule TTP_XOR_MULT_DOSStub_b0b3 {
  strings:
    $key_b0b3 = { e4 db [2] 90 c3 [2] d7 c1 [2] 90 d0 [2] de dc [2] d2 d6 [2] c5 dd [2] de 93 [2] e3 }

  condition:
    any of them
}