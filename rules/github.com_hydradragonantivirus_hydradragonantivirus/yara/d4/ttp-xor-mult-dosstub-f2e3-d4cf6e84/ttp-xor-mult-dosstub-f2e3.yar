rule TTP_XOR_MULT_DOSStub_f2e3 {
  strings:
    $key_f2e3 = { a6 8b [2] d2 93 [2] 95 91 [2] d2 80 [2] 9c 8c [2] 90 86 [2] 87 8d [2] 9c c3 [2] a1 }

  condition:
    any of them
}