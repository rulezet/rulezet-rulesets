rule TTP_XOR_MULT_DOSStub_d7dd {
  strings:
    $key_d7dd = { 83 b5 [2] f7 ad [2] b0 af [2] f7 be [2] b9 b2 [2] b5 b8 [2] a2 b3 [2] b9 fd [2] 84 }

  condition:
    any of them
}