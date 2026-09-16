rule TTP_XOR_MULT_DOSStub_18a8 {
  strings:
    $key_18a8 = { 4c c0 [2] 38 d8 [2] 7f da [2] 38 cb [2] 76 c7 [2] 7a cd [2] 6d c6 [2] 76 88 [2] 4b }

  condition:
    any of them
}