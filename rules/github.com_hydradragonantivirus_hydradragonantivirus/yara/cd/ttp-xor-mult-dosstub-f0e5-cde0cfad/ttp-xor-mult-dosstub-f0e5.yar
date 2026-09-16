rule TTP_XOR_MULT_DOSStub_f0e5 {
  strings:
    $key_f0e5 = { a4 8d [2] d0 95 [2] 97 97 [2] d0 86 [2] 9e 8a [2] 92 80 [2] 85 8b [2] 9e c5 [2] a3 }

  condition:
    any of them
}