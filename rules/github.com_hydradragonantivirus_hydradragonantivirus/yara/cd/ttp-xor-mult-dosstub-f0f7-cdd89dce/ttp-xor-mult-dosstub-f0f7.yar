rule TTP_XOR_MULT_DOSStub_f0f7 {
  strings:
    $key_f0f7 = { a4 9f [2] d0 87 [2] 97 85 [2] d0 94 [2] 9e 98 [2] 92 92 [2] 85 99 [2] 9e d7 [2] a3 }

  condition:
    any of them
}