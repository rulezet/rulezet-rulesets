rule TTP_XOR_MULT_DOSStub_d57d {
  strings:
    $key_d57d = { 81 15 [2] f5 0d [2] b2 0f [2] f5 1e [2] bb 12 [2] b7 18 [2] a0 13 [2] bb 5d [2] 86 }

  condition:
    any of them
}