rule TTP_XOR_MULT_DOSStub_b2ec {
  strings:
    $key_b2ec = { e6 84 [2] 92 9c [2] d5 9e [2] 92 8f [2] dc 83 [2] d0 89 [2] c7 82 [2] dc cc [2] e1 }

  condition:
    any of them
}