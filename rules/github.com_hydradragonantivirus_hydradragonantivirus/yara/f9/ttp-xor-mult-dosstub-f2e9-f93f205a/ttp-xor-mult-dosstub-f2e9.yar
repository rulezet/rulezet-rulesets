rule TTP_XOR_MULT_DOSStub_f2e9 {
  strings:
    $key_f2e9 = { a6 81 [2] d2 99 [2] 95 9b [2] d2 8a [2] 9c 86 [2] 90 8c [2] 87 87 [2] 9c c9 [2] a1 }

  condition:
    any of them
}