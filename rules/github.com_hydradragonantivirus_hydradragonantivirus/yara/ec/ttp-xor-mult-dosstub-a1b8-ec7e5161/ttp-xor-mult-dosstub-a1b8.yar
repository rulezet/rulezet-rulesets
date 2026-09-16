rule TTP_XOR_MULT_DOSStub_a1b8 {
  strings:
    $key_a1b8 = { f5 d0 [2] 81 c8 [2] c6 ca [2] 81 db [2] cf d7 [2] c3 dd [2] d4 d6 [2] cf 98 [2] f2 }

  condition:
    any of them
}