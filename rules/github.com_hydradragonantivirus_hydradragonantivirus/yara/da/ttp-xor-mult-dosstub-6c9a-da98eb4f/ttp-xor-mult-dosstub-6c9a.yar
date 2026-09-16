rule TTP_XOR_MULT_DOSStub_6c9a {
  strings:
    $key_6c9a = { 38 f2 [2] 4c ea [2] 0b e8 [2] 4c f9 [2] 02 f5 [2] 0e ff [2] 19 f4 [2] 02 ba [2] 3f }

  condition:
    any of them
}