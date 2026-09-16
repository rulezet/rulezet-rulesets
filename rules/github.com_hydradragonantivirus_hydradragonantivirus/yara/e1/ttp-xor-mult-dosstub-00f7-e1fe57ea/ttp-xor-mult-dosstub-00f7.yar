rule TTP_XOR_MULT_DOSStub_00f7 {
  strings:
    $key_00f7 = { 54 9f [2] 20 87 [2] 67 85 [2] 20 94 [2] 6e 98 [2] 62 92 [2] 75 99 [2] 6e d7 [2] 53 }

  condition:
    any of them
}