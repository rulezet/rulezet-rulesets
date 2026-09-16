rule TTP_XOR_MULT_DOSStub_f2f5 {
  strings:
    $key_f2f5 = { a6 9d [2] d2 85 [2] 95 87 [2] d2 96 [2] 9c 9a [2] 90 90 [2] 87 9b [2] 9c d5 [2] a1 }

  condition:
    any of them
}