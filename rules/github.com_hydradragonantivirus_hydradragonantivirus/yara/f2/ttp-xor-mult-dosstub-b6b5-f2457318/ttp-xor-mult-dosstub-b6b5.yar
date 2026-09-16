rule TTP_XOR_MULT_DOSStub_b6b5 {
  strings:
    $key_b6b5 = { e2 dd [2] 96 c5 [2] d1 c7 [2] 96 d6 [2] d8 da [2] d4 d0 [2] c3 db [2] d8 95 [2] e5 }

  condition:
    any of them
}