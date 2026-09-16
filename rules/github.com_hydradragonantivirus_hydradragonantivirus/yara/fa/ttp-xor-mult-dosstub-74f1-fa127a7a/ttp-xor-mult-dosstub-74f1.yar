rule TTP_XOR_MULT_DOSStub_74f1 {
  strings:
    $key_74f1 = { 20 99 [2] 54 81 [2] 13 83 [2] 54 92 [2] 1a 9e [2] 16 94 [2] 01 9f [2] 1a d1 [2] 27 }

  condition:
    any of them
}