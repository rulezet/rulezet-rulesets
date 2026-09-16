rule TTP_XOR_MULT_DOSStub_86ad {
  strings:
    $key_86ad = { d2 c5 [2] a6 dd [2] e1 df [2] a6 ce [2] e8 c2 [2] e4 c8 [2] f3 c3 [2] e8 8d [2] d5 }

  condition:
    any of them
}