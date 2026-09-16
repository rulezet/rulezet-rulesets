rule TTP_XOR_MULT_DOSStub_1aad {
  strings:
    $key_1aad = { 4e c5 [2] 3a dd [2] 7d df [2] 3a ce [2] 74 c2 [2] 78 c8 [2] 6f c3 [2] 74 8d [2] 49 }

  condition:
    any of them
}