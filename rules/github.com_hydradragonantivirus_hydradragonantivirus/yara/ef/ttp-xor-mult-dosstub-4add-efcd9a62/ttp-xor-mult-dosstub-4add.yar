rule TTP_XOR_MULT_DOSStub_4add {
  strings:
    $key_4add = { 1e b5 [2] 6a ad [2] 2d af [2] 6a be [2] 24 b2 [2] 28 b8 [2] 3f b3 [2] 24 fd [2] 19 }

  condition:
    any of them
}