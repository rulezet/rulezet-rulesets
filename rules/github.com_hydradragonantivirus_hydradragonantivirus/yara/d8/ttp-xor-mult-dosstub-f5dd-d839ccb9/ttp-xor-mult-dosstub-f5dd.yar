rule TTP_XOR_MULT_DOSStub_f5dd {
  strings:
    $key_f5dd = { a1 b5 [2] d5 ad [2] 92 af [2] d5 be [2] 9b b2 [2] 97 b8 [2] 80 b3 [2] 9b fd [2] a6 }

  condition:
    any of them
}