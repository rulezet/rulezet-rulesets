rule TTP_XOR_MULT_DOSStub_b4b3 {
  strings:
    $key_b4b3 = { e0 db [2] 94 c3 [2] d3 c1 [2] 94 d0 [2] da dc [2] d6 d6 [2] c1 dd [2] da 93 [2] e7 }

  condition:
    any of them
}