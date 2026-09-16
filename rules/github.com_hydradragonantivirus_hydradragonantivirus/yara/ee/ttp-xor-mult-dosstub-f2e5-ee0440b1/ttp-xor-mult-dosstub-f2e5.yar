rule TTP_XOR_MULT_DOSStub_f2e5 {
  strings:
    $key_f2e5 = { a6 8d [2] d2 95 [2] 95 97 [2] d2 86 [2] 9c 8a [2] 90 80 [2] 87 8b [2] 9c c5 [2] a1 }

  condition:
    any of them
}