rule TTP_XOR_MULT_DOSStub_c8dd {
  strings:
    $key_c8dd = { 9c b5 [2] e8 ad [2] af af [2] e8 be [2] a6 b2 [2] aa b8 [2] bd b3 [2] a6 fd [2] 9b }

  condition:
    any of them
}