rule TTP_XOR_MULT_DOSStub_f0f6 {
  strings:
    $key_f0f6 = { a4 9e [2] d0 86 [2] 97 84 [2] d0 95 [2] 9e 99 [2] 92 93 [2] 85 98 [2] 9e d6 [2] a3 }

  condition:
    any of them
}