rule TTP_XOR_MULT_DOSStub_39ad {
  strings:
    $key_39ad = { 6d c5 [2] 19 dd [2] 5e df [2] 19 ce [2] 57 c2 [2] 5b c8 [2] 4c c3 [2] 57 8d [2] 6a }

  condition:
    any of them
}