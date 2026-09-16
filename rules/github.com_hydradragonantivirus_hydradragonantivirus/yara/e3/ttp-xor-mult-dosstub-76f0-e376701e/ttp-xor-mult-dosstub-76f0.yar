rule TTP_XOR_MULT_DOSStub_76f0 {
  strings:
    $key_76f0 = { 22 98 [2] 56 80 [2] 11 82 [2] 56 93 [2] 18 9f [2] 14 95 [2] 03 9e [2] 18 d0 [2] 25 }

  condition:
    any of them
}