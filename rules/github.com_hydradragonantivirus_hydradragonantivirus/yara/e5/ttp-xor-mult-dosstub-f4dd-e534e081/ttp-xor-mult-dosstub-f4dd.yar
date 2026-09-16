rule TTP_XOR_MULT_DOSStub_f4dd {
  strings:
    $key_f4dd = { a0 b5 [2] d4 ad [2] 93 af [2] d4 be [2] 9a b2 [2] 96 b8 [2] 81 b3 [2] 9a fd [2] a7 }

  condition:
    any of them
}