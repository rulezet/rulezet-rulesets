rule TTP_XOR_MULT_DOSStub_f23e {
  strings:
    $key_f23e = { a6 56 [2] d2 4e [2] 95 4c [2] d2 5d [2] 9c 51 [2] 90 5b [2] 87 50 [2] 9c 1e [2] a1 }

  condition:
    any of them
}