rule TTP_XOR_MULT_DOSStub_048d {
  strings:
    $key_048d = { 50 e5 [2] 24 fd [2] 63 ff [2] 24 ee [2] 6a e2 [2] 66 e8 [2] 71 e3 [2] 6a ad [2] 57 }

  condition:
    any of them
}