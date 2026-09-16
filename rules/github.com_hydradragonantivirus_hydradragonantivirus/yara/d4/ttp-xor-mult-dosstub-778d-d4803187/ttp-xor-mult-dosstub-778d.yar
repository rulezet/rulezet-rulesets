rule TTP_XOR_MULT_DOSStub_778d {
  strings:
    $key_778d = { 23 e5 [2] 57 fd [2] 10 ff [2] 57 ee [2] 19 e2 [2] 15 e8 [2] 02 e3 [2] 19 ad [2] 24 }

  condition:
    any of them
}