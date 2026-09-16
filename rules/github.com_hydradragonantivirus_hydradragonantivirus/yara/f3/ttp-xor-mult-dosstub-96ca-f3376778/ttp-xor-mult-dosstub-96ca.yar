rule TTP_XOR_MULT_DOSStub_96ca {
  strings:
    $key_96ca = { c2 a2 [2] b6 ba [2] f1 b8 [2] b6 a9 [2] f8 a5 [2] f4 af [2] e3 a4 [2] f8 ea [2] c5 }

  condition:
    any of them
}