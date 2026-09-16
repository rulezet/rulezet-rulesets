rule TTP_XOR_MULT_DOSStub_a0b5 {
  strings:
    $key_a0b5 = { f4 dd [2] 80 c5 [2] c7 c7 [2] 80 d6 [2] ce da [2] c2 d0 [2] d5 db [2] ce 95 [2] f3 }

  condition:
    any of them
}