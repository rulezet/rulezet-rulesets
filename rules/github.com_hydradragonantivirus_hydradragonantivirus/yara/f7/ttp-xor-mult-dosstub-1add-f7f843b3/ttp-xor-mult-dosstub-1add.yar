rule TTP_XOR_MULT_DOSStub_1add {
  strings:
    $key_1add = { 4e b5 [2] 3a ad [2] 7d af [2] 3a be [2] 74 b2 [2] 78 b8 [2] 6f b3 [2] 74 fd [2] 49 }

  condition:
    any of them
}