rule TTP_XOR_MULT_DOSStub_26f1 {
  strings:
    $key_26f1 = { 72 99 [2] 06 81 [2] 41 83 [2] 06 92 [2] 48 9e [2] 44 94 [2] 53 9f [2] 48 d1 [2] 75 }

  condition:
    any of them
}