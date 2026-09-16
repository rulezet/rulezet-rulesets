rule TTP_XOR_MULT_DOSStub_72f7 {
  strings:
    $key_72f7 = { 26 9f [2] 52 87 [2] 15 85 [2] 52 94 [2] 1c 98 [2] 10 92 [2] 07 99 [2] 1c d7 [2] 21 }

  condition:
    any of them
}