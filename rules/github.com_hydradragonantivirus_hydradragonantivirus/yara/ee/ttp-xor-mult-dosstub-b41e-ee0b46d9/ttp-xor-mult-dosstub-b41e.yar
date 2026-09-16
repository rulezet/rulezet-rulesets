rule TTP_XOR_MULT_DOSStub_b41e {
  strings:
    $key_b41e = { e0 76 [2] 94 6e [2] d3 6c [2] 94 7d [2] da 71 [2] d6 7b [2] c1 70 [2] da 3e [2] e7 }

  condition:
    any of them
}