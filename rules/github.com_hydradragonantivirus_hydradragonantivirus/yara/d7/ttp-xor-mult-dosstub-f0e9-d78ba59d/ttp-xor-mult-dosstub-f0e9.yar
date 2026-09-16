rule TTP_XOR_MULT_DOSStub_f0e9 {
  strings:
    $key_f0e9 = { a4 81 [2] d0 99 [2] 97 9b [2] d0 8a [2] 9e 86 [2] 92 8c [2] 85 87 [2] 9e c9 [2] a3 }

  condition:
    any of them
}