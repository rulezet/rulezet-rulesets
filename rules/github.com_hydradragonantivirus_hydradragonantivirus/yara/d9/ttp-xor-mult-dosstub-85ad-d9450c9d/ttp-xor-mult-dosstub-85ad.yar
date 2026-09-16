rule TTP_XOR_MULT_DOSStub_85ad {
  strings:
    $key_85ad = { d1 c5 [2] a5 dd [2] e2 df [2] a5 ce [2] eb c2 [2] e7 c8 [2] f0 c3 [2] eb 8d [2] d6 }

  condition:
    any of them
}