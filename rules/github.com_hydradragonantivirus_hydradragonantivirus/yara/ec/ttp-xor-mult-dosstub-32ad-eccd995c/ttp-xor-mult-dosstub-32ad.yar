rule TTP_XOR_MULT_DOSStub_32ad {
  strings:
    $key_32ad = { 66 c5 [2] 12 dd [2] 55 df [2] 12 ce [2] 5c c2 [2] 50 c8 [2] 47 c3 [2] 5c 8d [2] 61 }

  condition:
    any of them
}