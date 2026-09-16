rule TTP_XOR_MULT_DOSStub_d6ad {
  strings:
    $key_d6ad = { 82 c5 [2] f6 dd [2] b1 df [2] f6 ce [2] b8 c2 [2] b4 c8 [2] a3 c3 [2] b8 8d [2] 85 }

  condition:
    any of them
}