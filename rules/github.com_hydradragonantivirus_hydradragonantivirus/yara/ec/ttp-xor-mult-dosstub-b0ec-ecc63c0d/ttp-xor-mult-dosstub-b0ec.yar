rule TTP_XOR_MULT_DOSStub_b0ec {
  strings:
    $key_b0ec = { e4 84 [2] 90 9c [2] d7 9e [2] 90 8f [2] de 83 [2] d2 89 [2] c5 82 [2] de cc [2] e3 }

  condition:
    any of them
}