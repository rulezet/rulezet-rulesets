rule TTP_XOR_MULT_DOSStub_b1b5 {
  strings:
    $key_b1b5 = { e5 dd [2] 91 c5 [2] d6 c7 [2] 91 d6 [2] df da [2] d3 d0 [2] c4 db [2] df 95 [2] e2 }

  condition:
    any of them
}