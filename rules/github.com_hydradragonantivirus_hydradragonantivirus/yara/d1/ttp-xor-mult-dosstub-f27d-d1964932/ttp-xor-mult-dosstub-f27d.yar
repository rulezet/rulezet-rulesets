rule TTP_XOR_MULT_DOSStub_f27d {
  strings:
    $key_f27d = { a6 15 [2] d2 0d [2] 95 0f [2] d2 1e [2] 9c 12 [2] 90 18 [2] 87 13 [2] 9c 5d [2] a1 }

  condition:
    any of them
}