rule TTP_XOR_MULT_DOSStub_f27e {
  strings:
    $key_f27e = { a6 16 [2] d2 0e [2] 95 0c [2] d2 1d [2] 9c 11 [2] 90 1b [2] 87 10 [2] 9c 5e [2] a1 }

  condition:
    any of them
}