rule TTP_XOR_MULT_DOSStub_93ca {
  strings:
    $key_93ca = { c7 a2 [2] b3 ba [2] f4 b8 [2] b3 a9 [2] fd a5 [2] f1 af [2] e6 a4 [2] fd ea [2] c0 }

  condition:
    any of them
}