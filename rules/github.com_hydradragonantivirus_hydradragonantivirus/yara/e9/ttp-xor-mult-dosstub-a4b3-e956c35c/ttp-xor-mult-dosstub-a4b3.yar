rule TTP_XOR_MULT_DOSStub_a4b3 {
  strings:
    $key_a4b3 = { f0 db [2] 84 c3 [2] c3 c1 [2] 84 d0 [2] ca dc [2] c6 d6 [2] d1 dd [2] ca 93 [2] f7 }

  condition:
    any of them
}