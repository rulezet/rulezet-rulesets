rule TTP_XOR_MULT_DOSStub_f7e2 {
  strings:
    $key_f7e2 = { a3 8a [2] d7 92 [2] 90 90 [2] d7 81 [2] 99 8d [2] 95 87 [2] 82 8c [2] 99 c2 [2] a4 }

  condition:
    any of them
}