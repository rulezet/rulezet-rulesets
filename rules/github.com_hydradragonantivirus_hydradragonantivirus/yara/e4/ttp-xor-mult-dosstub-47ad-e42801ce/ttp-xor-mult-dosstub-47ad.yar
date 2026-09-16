rule TTP_XOR_MULT_DOSStub_47ad {
  strings:
    $key_47ad = { 13 c5 [2] 67 dd [2] 20 df [2] 67 ce [2] 29 c2 [2] 25 c8 [2] 32 c3 [2] 29 8d [2] 14 }

  condition:
    any of them
}