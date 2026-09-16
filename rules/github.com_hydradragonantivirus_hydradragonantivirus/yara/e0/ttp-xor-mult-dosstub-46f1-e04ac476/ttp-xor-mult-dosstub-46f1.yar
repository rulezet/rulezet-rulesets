rule TTP_XOR_MULT_DOSStub_46f1 {
  strings:
    $key_46f1 = { 12 99 [2] 66 81 [2] 21 83 [2] 66 92 [2] 28 9e [2] 24 94 [2] 33 9f [2] 28 d1 [2] 15 }

  condition:
    any of them
}