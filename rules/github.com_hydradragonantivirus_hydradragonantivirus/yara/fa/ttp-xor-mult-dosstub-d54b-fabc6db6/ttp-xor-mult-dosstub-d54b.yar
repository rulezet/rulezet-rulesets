rule TTP_XOR_MULT_DOSStub_d54b {
  strings:
    $key_d54b = { 81 23 [2] f5 3b [2] b2 39 [2] f5 28 [2] bb 24 [2] b7 2e [2] a0 25 [2] bb 6b [2] 86 }

  condition:
    any of them
}