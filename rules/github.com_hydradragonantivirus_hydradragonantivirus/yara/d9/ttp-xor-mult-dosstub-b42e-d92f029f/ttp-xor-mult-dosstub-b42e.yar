rule TTP_XOR_MULT_DOSStub_b42e {
  strings:
    $key_b42e = { e0 46 [2] 94 5e [2] d3 5c [2] 94 4d [2] da 41 [2] d6 4b [2] c1 40 [2] da 0e [2] e7 }

  condition:
    any of them
}