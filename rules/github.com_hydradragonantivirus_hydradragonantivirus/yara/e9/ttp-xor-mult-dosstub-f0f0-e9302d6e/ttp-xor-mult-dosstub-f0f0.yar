rule TTP_XOR_MULT_DOSStub_f0f0 {
  strings:
    $key_f0f0 = { a4 98 [2] d0 80 [2] 97 82 [2] d0 93 [2] 9e 9f [2] 92 95 [2] 85 9e [2] 9e d0 [2] a3 }

  condition:
    any of them
}