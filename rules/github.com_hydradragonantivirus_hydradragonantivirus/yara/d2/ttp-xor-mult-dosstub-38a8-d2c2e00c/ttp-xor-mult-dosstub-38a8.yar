rule TTP_XOR_MULT_DOSStub_38a8 {
  strings:
    $key_38a8 = { 6c c0 [2] 18 d8 [2] 5f da [2] 18 cb [2] 56 c7 [2] 5a cd [2] 4d c6 [2] 56 88 [2] 6b }

  condition:
    any of them
}