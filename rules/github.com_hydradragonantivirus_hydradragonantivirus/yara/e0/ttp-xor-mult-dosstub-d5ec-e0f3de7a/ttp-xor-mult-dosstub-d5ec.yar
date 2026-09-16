rule TTP_XOR_MULT_DOSStub_d5ec {
  strings:
    $key_d5ec = { 81 84 [2] f5 9c [2] b2 9e [2] f5 8f [2] bb 83 [2] b7 89 [2] a0 82 [2] bb cc [2] 86 }

  condition:
    any of them
}