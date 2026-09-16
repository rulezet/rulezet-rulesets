rule TTP_XOR_MULT_DOSStub_41f0 {
  strings:
    $key_41f0 = { 15 98 [2] 61 80 [2] 26 82 [2] 61 93 [2] 2f 9f [2] 23 95 [2] 34 9e [2] 2f d0 [2] 12 }

  condition:
    any of them
}