rule TTP_XOR_MULT_DOSStub_36f7 {
  strings:
    $key_36f7 = { 62 9f [2] 16 87 [2] 51 85 [2] 16 94 [2] 58 98 [2] 54 92 [2] 43 99 [2] 58 d7 [2] 65 }

  condition:
    any of them
}