rule TTP_XOR_MULT_DOSStub_e4dd {
  strings:
    $key_e4dd = { b0 b5 [2] c4 ad [2] 83 af [2] c4 be [2] 8a b2 [2] 86 b8 [2] 91 b3 [2] 8a fd [2] b7 }

  condition:
    any of them
}