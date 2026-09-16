rule TTP_XOR_MULT_DOSStub_d6ca {
  strings:
    $key_d6ca = { 82 a2 [2] f6 ba [2] b1 b8 [2] f6 a9 [2] b8 a5 [2] b4 af [2] a3 a4 [2] b8 ea [2] 85 }

  condition:
    any of them
}