rule TTP_XOR_MULT_DOSStub_35ad {
  strings:
    $key_35ad = { 61 c5 [2] 15 dd [2] 52 df [2] 15 ce [2] 5b c2 [2] 57 c8 [2] 40 c3 [2] 5b 8d [2] 66 }

  condition:
    any of them
}