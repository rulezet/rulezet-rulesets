rule TTP_XOR_MULT_DOSStub_049a {
  strings:
    $key_049a = { 50 f2 [2] 24 ea [2] 63 e8 [2] 24 f9 [2] 6a f5 [2] 66 ff [2] 71 f4 [2] 6a ba [2] 57 }

  condition:
    any of them
}