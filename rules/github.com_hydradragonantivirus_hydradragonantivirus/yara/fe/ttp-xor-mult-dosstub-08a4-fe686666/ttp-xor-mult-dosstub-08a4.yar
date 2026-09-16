rule TTP_XOR_MULT_DOSStub_08a4 {
  strings:
    $key_08a4 = { 5c cc [2] 28 d4 [2] 6f d6 [2] 28 c7 [2] 66 cb [2] 6a c1 [2] 7d ca [2] 66 84 [2] 5b }

  condition:
    any of them
}