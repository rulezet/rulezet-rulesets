rule TTP_XOR_MULT_DOSStub_338d {
  strings:
    $key_338d = { 67 e5 [2] 13 fd [2] 54 ff [2] 13 ee [2] 5d e2 [2] 51 e8 [2] 46 e3 [2] 5d ad [2] 60 }

  condition:
    any of them
}