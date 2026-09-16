rule TTP_XOR_MULT_DOSStub_8eca {
  strings:
    $key_8eca = { da a2 [2] ae ba [2] e9 b8 [2] ae a9 [2] e0 a5 [2] ec af [2] fb a4 [2] e0 ea [2] dd }

  condition:
    any of them
}