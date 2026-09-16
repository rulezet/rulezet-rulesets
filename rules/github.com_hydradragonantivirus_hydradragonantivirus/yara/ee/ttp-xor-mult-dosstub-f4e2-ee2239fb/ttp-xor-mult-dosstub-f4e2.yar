rule TTP_XOR_MULT_DOSStub_f4e2 {
  strings:
    $key_f4e2 = { a0 8a [2] d4 92 [2] 93 90 [2] d4 81 [2] 9a 8d [2] 96 87 [2] 81 8c [2] 9a c2 [2] a7 }

  condition:
    any of them
}