rule TTP_XOR_MULT_DOSStub_06dd {
  strings:
    $key_06dd = { 52 b5 [2] 26 ad [2] 61 af [2] 26 be [2] 68 b2 [2] 64 b8 [2] 73 b3 [2] 68 fd [2] 55 }

  condition:
    any of them
}