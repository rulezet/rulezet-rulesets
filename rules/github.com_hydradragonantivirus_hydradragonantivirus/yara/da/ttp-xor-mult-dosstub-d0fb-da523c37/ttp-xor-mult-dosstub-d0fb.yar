rule TTP_XOR_MULT_DOSStub_d0fb {
  strings:
    $key_d0fb = { 84 93 [2] f0 8b [2] b7 89 [2] f0 98 [2] be 94 [2] b2 9e [2] a5 95 [2] be db [2] 83 }

  condition:
    any of them
}