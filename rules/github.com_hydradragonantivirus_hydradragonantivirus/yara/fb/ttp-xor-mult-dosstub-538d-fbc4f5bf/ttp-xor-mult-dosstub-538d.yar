rule TTP_XOR_MULT_DOSStub_538d {
  strings:
    $key_538d = { 07 e5 [2] 73 fd [2] 34 ff [2] 73 ee [2] 3d e2 [2] 31 e8 [2] 26 e3 [2] 3d ad [2] 00 }

  condition:
    any of them
}