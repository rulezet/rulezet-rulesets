rule TTP_XOR_MULT_DOSStub_c1ec {
  strings:
    $key_c1ec = { 95 84 [2] e1 9c [2] a6 9e [2] e1 8f [2] af 83 [2] a3 89 [2] b4 82 [2] af cc [2] 92 }

  condition:
    any of them
}