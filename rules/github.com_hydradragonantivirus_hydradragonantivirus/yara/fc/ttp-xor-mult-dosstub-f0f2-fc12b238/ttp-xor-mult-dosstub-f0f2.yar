rule TTP_XOR_MULT_DOSStub_f0f2 {
  strings:
    $key_f0f2 = { a4 9a [2] d0 82 [2] 97 80 [2] d0 91 [2] 9e 9d [2] 92 97 [2] 85 9c [2] 9e d2 [2] a3 }

  condition:
    any of them
}