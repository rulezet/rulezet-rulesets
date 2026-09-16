rule TTP_XOR_MULT_DOSStub_a1b5 {
  strings:
    $key_a1b5 = { f5 dd [2] 81 c5 [2] c6 c7 [2] 81 d6 [2] cf da [2] c3 d0 [2] d4 db [2] cf 95 [2] f2 }

  condition:
    any of them
}