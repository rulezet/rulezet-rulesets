rule TTP_XOR_MULT_DOSStub_46f7 {
  strings:
    $key_46f7 = { 12 9f [2] 66 87 [2] 21 85 [2] 66 94 [2] 28 98 [2] 24 92 [2] 33 99 [2] 28 d7 [2] 15 }

  condition:
    any of them
}