rule TTP_XOR_MULT_DOSStub_46ad {
  strings:
    $key_46ad = { 12 c5 [2] 66 dd [2] 21 df [2] 66 ce [2] 28 c2 [2] 24 c8 [2] 33 c3 [2] 28 8d [2] 15 }

  condition:
    any of them
}