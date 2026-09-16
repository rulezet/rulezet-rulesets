rule TTP_XOR_MULT_DOSStub_8ec1 {
  strings:
    $key_8ec1 = { da a9 [2] ae b1 [2] e9 b3 [2] ae a2 [2] e0 ae [2] ec a4 [2] fb af [2] e0 e1 [2] dd }

  condition:
    any of them
}