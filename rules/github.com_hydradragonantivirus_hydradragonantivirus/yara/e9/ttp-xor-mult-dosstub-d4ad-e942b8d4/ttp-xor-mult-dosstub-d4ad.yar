rule TTP_XOR_MULT_DOSStub_d4ad {
  strings:
    $key_d4ad = { 80 c5 [2] f4 dd [2] b3 df [2] f4 ce [2] ba c2 [2] b6 c8 [2] a1 c3 [2] ba 8d [2] 87 }

  condition:
    any of them
}