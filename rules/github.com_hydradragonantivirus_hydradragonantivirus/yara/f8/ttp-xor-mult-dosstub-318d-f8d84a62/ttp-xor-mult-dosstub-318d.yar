rule TTP_XOR_MULT_DOSStub_318d {
  strings:
    $key_318d = { 65 e5 [2] 11 fd [2] 56 ff [2] 11 ee [2] 5f e2 [2] 53 e8 [2] 44 e3 [2] 5f ad [2] 62 }

  condition:
    any of them
}