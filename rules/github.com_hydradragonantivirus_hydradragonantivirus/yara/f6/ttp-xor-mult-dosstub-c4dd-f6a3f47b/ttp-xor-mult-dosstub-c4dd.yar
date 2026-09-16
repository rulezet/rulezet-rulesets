rule TTP_XOR_MULT_DOSStub_c4dd {
  strings:
    $key_c4dd = { 90 b5 [2] e4 ad [2] a3 af [2] e4 be [2] aa b2 [2] a6 b8 [2] b1 b3 [2] aa fd [2] 97 }

  condition:
    any of them
}