rule TTP_XOR_MULT_DOSStub_d0ca {
  strings:
    $key_d0ca = { 84 a2 [2] f0 ba [2] b7 b8 [2] f0 a9 [2] be a5 [2] b2 af [2] a5 a4 [2] be ea [2] 83 }

  condition:
    any of them
}