rule TTP_XOR_MULT_DOSStub_95ad {
  strings:
    $key_95ad = { c1 c5 [2] b5 dd [2] f2 df [2] b5 ce [2] fb c2 [2] f7 c8 [2] e0 c3 [2] fb 8d [2] c6 }

  condition:
    any of them
}