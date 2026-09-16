rule TTP_XOR_MULT_DOSStub_39ab {
  strings:
    $key_39ab = { 6d c3 [2] 19 db [2] 5e d9 [2] 19 c8 [2] 57 c4 [2] 5b ce [2] 4c c5 [2] 57 8b [2] 6a }

  condition:
    any of them
}