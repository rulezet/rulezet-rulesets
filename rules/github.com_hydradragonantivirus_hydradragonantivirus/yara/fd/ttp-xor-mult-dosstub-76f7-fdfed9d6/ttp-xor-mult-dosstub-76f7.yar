rule TTP_XOR_MULT_DOSStub_76f7 {
  strings:
    $key_76f7 = { 22 9f [2] 56 87 [2] 11 85 [2] 56 94 [2] 18 98 [2] 14 92 [2] 03 99 [2] 18 d7 [2] 25 }

  condition:
    any of them
}