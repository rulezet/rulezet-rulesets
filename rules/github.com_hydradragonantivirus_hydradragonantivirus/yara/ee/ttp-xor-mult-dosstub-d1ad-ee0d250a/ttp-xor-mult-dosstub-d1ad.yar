rule TTP_XOR_MULT_DOSStub_d1ad {
  strings:
    $key_d1ad = { 85 c5 [2] f1 dd [2] b6 df [2] f1 ce [2] bf c2 [2] b3 c8 [2] a4 c3 [2] bf 8d [2] 82 }

  condition:
    any of them
}