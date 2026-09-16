rule TTP_XOR_MULT_DOSStub_d7b5 {
  strings:
    $key_d7b5 = { 83 dd [2] f7 c5 [2] b0 c7 [2] f7 d6 [2] b9 da [2] b5 d0 [2] a2 db [2] b9 95 [2] 84 }

  condition:
    any of them
}