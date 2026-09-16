rule TTP_XOR_MULT_DOSStub_39a8 {
  strings:
    $key_39a8 = { 6d c0 [2] 19 d8 [2] 5e da [2] 19 cb [2] 57 c7 [2] 5b cd [2] 4c c6 [2] 57 88 [2] 6a }

  condition:
    any of them
}