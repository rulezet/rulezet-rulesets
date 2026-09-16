rule TTP_XOR_MULT_DOSStub_3863 {
  strings:
    $key_3863 = { 6c 0b [2] 18 13 [2] 5f 11 [2] 18 00 [2] 56 0c [2] 5a 06 [2] 4d 0d [2] 56 43 [2] 6b }

  condition:
    any of them
}