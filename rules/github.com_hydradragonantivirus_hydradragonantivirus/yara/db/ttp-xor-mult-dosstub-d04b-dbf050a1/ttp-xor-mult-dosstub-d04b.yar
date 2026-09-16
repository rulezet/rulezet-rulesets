rule TTP_XOR_MULT_DOSStub_d04b {
  strings:
    $key_d04b = { 84 23 [2] f0 3b [2] b7 39 [2] f0 28 [2] be 24 [2] b2 2e [2] a5 25 [2] be 6b [2] 83 }

  condition:
    any of them
}