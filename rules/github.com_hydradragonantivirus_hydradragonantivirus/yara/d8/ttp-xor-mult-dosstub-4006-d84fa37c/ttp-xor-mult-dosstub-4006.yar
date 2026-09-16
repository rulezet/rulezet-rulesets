rule TTP_XOR_MULT_DOSStub_4006 {
  strings:
    $key_4006 = { 14 6e [2] 60 76 [2] 27 74 [2] 60 65 [2] 2e 69 [2] 22 63 [2] 35 68 [2] 2e 26 [2] 13 }

  condition:
    any of them
}