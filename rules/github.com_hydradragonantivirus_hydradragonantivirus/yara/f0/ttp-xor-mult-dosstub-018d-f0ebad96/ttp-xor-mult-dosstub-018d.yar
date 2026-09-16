rule TTP_XOR_MULT_DOSStub_018d {
  strings:
    $key_018d = { 55 e5 [2] 21 fd [2] 66 ff [2] 21 ee [2] 6f e2 [2] 63 e8 [2] 74 e3 [2] 6f ad [2] 52 }

  condition:
    any of them
}