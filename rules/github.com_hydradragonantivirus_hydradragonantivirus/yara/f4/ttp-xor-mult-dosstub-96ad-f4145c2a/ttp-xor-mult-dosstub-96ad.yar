rule TTP_XOR_MULT_DOSStub_96ad {
  strings:
    $key_96ad = { c2 c5 [2] b6 dd [2] f1 df [2] b6 ce [2] f8 c2 [2] f4 c8 [2] e3 c3 [2] f8 8d [2] c5 }

  condition:
    any of them
}