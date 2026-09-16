rule TTP_XOR_MULT_DOSStub_76f1 {
  strings:
    $key_76f1 = { 22 99 [2] 56 81 [2] 11 83 [2] 56 92 [2] 18 9e [2] 14 94 [2] 03 9f [2] 18 d1 [2] 25 }

  condition:
    any of them
}