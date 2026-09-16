rule TTP_XOR_MULT_DOSStub_aeca {
  strings:
    $key_aeca = { fa a2 [2] 8e ba [2] c9 b8 [2] 8e a9 [2] c0 a5 [2] cc af [2] db a4 [2] c0 ea [2] fd }

  condition:
    any of them
}