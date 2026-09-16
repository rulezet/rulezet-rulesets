rule TTP_XOR_MULT_DOSStub_249a {
  strings:
    $key_249a = { 70 f2 [2] 04 ea [2] 43 e8 [2] 04 f9 [2] 4a f5 [2] 46 ff [2] 51 f4 [2] 4a ba [2] 77 }

  condition:
    any of them
}