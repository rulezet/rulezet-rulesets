rule TTP_XOR_MULT_DOSStub_b0b5 {
  strings:
    $key_b0b5 = { e4 dd [2] 90 c5 [2] d7 c7 [2] 90 d6 [2] de da [2] d2 d0 [2] c5 db [2] de 95 [2] e3 }

  condition:
    any of them
}