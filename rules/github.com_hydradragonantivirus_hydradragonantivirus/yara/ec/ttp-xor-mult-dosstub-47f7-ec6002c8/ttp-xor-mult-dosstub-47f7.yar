rule TTP_XOR_MULT_DOSStub_47f7 {
  strings:
    $key_47f7 = { 13 9f [2] 67 87 [2] 20 85 [2] 67 94 [2] 29 98 [2] 25 92 [2] 32 99 [2] 29 d7 [2] 14 }

  condition:
    any of them
}