rule TTP_XOR_MULT_DOSStub_d9ad {
  strings:
    $key_d9ad = { 8d c5 [2] f9 dd [2] be df [2] f9 ce [2] b7 c2 [2] bb c8 [2] ac c3 [2] b7 8d [2] 8a }

  condition:
    any of them
}