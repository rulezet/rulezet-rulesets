rule TTP_XOR_MULT_DOSStub_d5ad {
  strings:
    $key_d5ad = { 81 c5 [2] f5 dd [2] b2 df [2] f5 ce [2] bb c2 [2] b7 c8 [2] a0 c3 [2] bb 8d [2] 86 }

  condition:
    any of them
}