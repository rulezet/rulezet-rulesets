rule TTP_XOR_MULT_DOSStub_3eb1 {
  strings:
    $key_3eb1 = { 6a d9 [2] 1e c1 [2] 59 c3 [2] 1e d2 [2] 50 de [2] 5c d4 [2] 4b df [2] 50 91 [2] 6d }

  condition:
    any of them
}