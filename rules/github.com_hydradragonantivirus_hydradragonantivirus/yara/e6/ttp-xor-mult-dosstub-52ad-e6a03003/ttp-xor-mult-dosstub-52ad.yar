rule TTP_XOR_MULT_DOSStub_52ad {
  strings:
    $key_52ad = { 06 c5 [2] 72 dd [2] 35 df [2] 72 ce [2] 3c c2 [2] 30 c8 [2] 27 c3 [2] 3c 8d [2] 01 }

  condition:
    any of them
}