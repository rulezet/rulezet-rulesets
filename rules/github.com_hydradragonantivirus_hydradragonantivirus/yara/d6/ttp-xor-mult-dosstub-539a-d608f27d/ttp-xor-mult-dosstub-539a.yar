rule TTP_XOR_MULT_DOSStub_539a {
  strings:
    $key_539a = { 07 f2 [2] 73 ea [2] 34 e8 [2] 73 f9 [2] 3d f5 [2] 31 ff [2] 26 f4 [2] 3d ba [2] 00 }

  condition:
    any of them
}