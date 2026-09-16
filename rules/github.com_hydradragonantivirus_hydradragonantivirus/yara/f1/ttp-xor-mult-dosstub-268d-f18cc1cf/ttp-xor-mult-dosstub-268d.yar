rule TTP_XOR_MULT_DOSStub_268d {
  strings:
    $key_268d = { 72 e5 [2] 06 fd [2] 41 ff [2] 06 ee [2] 48 e2 [2] 44 e8 [2] 53 e3 [2] 48 ad [2] 75 }

  condition:
    any of them
}