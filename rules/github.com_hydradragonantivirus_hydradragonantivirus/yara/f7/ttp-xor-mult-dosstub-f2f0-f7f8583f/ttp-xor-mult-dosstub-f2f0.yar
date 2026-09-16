rule TTP_XOR_MULT_DOSStub_f2f0 {
  strings:
    $key_f2f0 = { a6 98 [2] d2 80 [2] 95 82 [2] d2 93 [2] 9c 9f [2] 90 95 [2] 87 9e [2] 9c d0 [2] a1 }

  condition:
    any of them
}