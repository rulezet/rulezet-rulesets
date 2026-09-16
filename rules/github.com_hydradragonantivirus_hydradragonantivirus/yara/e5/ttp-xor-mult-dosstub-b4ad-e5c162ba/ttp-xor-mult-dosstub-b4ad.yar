rule TTP_XOR_MULT_DOSStub_b4ad {
  strings:
    $key_b4ad = { e0 c5 [2] 94 dd [2] d3 df [2] 94 ce [2] da c2 [2] d6 c8 [2] c1 c3 [2] da 8d [2] e7 }

  condition:
    any of them
}