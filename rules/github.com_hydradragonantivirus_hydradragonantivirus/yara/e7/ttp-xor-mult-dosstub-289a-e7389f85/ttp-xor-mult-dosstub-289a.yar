rule TTP_XOR_MULT_DOSStub_289a {
  strings:
    $key_289a = { 7c f2 [2] 08 ea [2] 4f e8 [2] 08 f9 [2] 46 f5 [2] 4a ff [2] 5d f4 [2] 46 ba [2] 7b }

  condition:
    any of them
}