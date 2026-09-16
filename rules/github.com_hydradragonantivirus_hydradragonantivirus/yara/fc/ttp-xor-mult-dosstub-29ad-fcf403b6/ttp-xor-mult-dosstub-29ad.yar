rule TTP_XOR_MULT_DOSStub_29ad {
  strings:
    $key_29ad = { 7d c5 [2] 09 dd [2] 4e df [2] 09 ce [2] 47 c2 [2] 4b c8 [2] 5c c3 [2] 47 8d [2] 7a }

  condition:
    any of them
}