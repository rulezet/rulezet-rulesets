rule TTP_XOR_MULT_DOSStub_07f1 {
  strings:
    $key_07f1 = { 53 99 [2] 27 81 [2] 60 83 [2] 27 92 [2] 69 9e [2] 65 94 [2] 72 9f [2] 69 d1 [2] 54 }

  condition:
    any of them
}