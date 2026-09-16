rule TTP_XOR_MULT_DOSStub_31f0 {
  strings:
    $key_31f0 = { 65 98 [2] 11 80 [2] 56 82 [2] 11 93 [2] 5f 9f [2] 53 95 [2] 44 9e [2] 5f d0 [2] 62 }

  condition:
    any of them
}