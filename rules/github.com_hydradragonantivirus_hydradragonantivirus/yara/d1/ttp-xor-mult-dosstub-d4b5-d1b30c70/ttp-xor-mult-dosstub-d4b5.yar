rule TTP_XOR_MULT_DOSStub_d4b5 {
  strings:
    $key_d4b5 = { 80 dd [2] f4 c5 [2] b3 c7 [2] f4 d6 [2] ba da [2] b6 d0 [2] a1 db [2] ba 95 [2] 87 }

  condition:
    any of them
}