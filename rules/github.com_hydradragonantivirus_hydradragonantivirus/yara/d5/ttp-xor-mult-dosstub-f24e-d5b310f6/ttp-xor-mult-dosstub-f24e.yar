rule TTP_XOR_MULT_DOSStub_f24e {
  strings:
    $key_f24e = { a6 26 [2] d2 3e [2] 95 3c [2] d2 2d [2] 9c 21 [2] 90 2b [2] 87 20 [2] 9c 6e [2] a1 }

  condition:
    any of them
}