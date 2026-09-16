rule TTP_XOR_MULT_DOSStub_13ad {
  strings:
    $key_13ad = { 47 c5 [2] 33 dd [2] 74 df [2] 33 ce [2] 7d c2 [2] 71 c8 [2] 66 c3 [2] 7d 8d [2] 40 }

  condition:
    any of them
}