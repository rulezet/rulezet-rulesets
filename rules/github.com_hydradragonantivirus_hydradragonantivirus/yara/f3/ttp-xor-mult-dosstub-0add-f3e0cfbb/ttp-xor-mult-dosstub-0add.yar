rule TTP_XOR_MULT_DOSStub_0add {
  strings:
    $key_0add = { 5e b5 [2] 2a ad [2] 6d af [2] 2a be [2] 64 b2 [2] 68 b8 [2] 7f b3 [2] 64 fd [2] 59 }

  condition:
    any of them
}