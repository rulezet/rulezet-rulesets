rule TTP_XOR_MULT_DOSStub_f2f1 {
  strings:
    $key_f2f1 = { a6 99 [2] d2 81 [2] 95 83 [2] d2 92 [2] 9c 9e [2] 90 94 [2] 87 9f [2] 9c d1 [2] a1 }

  condition:
    any of them
}