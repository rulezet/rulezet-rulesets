rule TTP_XOR_MULT_DOSStub_f0e4 {
  strings:
    $key_f0e4 = { a4 8c [2] d0 94 [2] 97 96 [2] d0 87 [2] 9e 8b [2] 92 81 [2] 85 8a [2] 9e c4 [2] a3 }

  condition:
    any of them
}