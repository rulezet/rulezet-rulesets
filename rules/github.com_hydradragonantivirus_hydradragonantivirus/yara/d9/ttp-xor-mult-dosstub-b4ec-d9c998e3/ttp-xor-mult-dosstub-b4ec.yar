rule TTP_XOR_MULT_DOSStub_b4ec {
  strings:
    $key_b4ec = { e0 84 [2] 94 9c [2] d3 9e [2] 94 8f [2] da 83 [2] d6 89 [2] c1 82 [2] da cc [2] e7 }

  condition:
    any of them
}