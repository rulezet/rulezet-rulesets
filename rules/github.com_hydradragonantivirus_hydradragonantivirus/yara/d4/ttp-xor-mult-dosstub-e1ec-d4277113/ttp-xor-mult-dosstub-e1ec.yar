rule TTP_XOR_MULT_DOSStub_e1ec {
  strings:
    $key_e1ec = { b5 84 [2] c1 9c [2] 86 9e [2] c1 8f [2] 8f 83 [2] 83 89 [2] 94 82 [2] 8f cc [2] b2 }

  condition:
    any of them
}