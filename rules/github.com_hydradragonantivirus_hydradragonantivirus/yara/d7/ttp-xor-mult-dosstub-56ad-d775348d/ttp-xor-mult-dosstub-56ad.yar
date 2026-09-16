rule TTP_XOR_MULT_DOSStub_56ad {
  strings:
    $key_56ad = { 02 c5 [2] 76 dd [2] 31 df [2] 76 ce [2] 38 c2 [2] 34 c8 [2] 23 c3 [2] 38 8d [2] 05 }

  condition:
    any of them
}