rule TTP_XOR_MULT_DOSStub_e0dd {
  strings:
    $key_e0dd = { b4 b5 [2] c0 ad [2] 87 af [2] c0 be [2] 8e b2 [2] 82 b8 [2] 95 b3 [2] 8e fd [2] b3 }

  condition:
    any of them
}