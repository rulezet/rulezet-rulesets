rule TTP_XOR_MULT_DOSStub_76e2 {
  strings:
    $key_76e2 = { 22 8a [2] 56 92 [2] 11 90 [2] 56 81 [2] 18 8d [2] 14 87 [2] 03 8c [2] 18 c2 [2] 25 }

  condition:
    any of them
}