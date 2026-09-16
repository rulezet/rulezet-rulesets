rule TTP_XOR_MULT_DOSStub_c0ec {
  strings:
    $key_c0ec = { 94 84 [2] e0 9c [2] a7 9e [2] e0 8f [2] ae 83 [2] a2 89 [2] b5 82 [2] ae cc [2] 93 }

  condition:
    any of them
}