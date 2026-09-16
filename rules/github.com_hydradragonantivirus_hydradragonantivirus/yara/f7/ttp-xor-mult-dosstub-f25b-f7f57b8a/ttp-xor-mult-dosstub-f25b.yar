rule TTP_XOR_MULT_DOSStub_f25b {
  strings:
    $key_f25b = { a6 33 [2] d2 2b [2] 95 29 [2] d2 38 [2] 9c 34 [2] 90 3e [2] 87 35 [2] 9c 7b [2] a1 }

  condition:
    any of them
}