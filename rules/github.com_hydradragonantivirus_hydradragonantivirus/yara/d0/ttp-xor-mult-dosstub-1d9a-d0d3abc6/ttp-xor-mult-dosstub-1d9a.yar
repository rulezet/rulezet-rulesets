rule TTP_XOR_MULT_DOSStub_1d9a {
  strings:
    $key_1d9a = { 49 f2 [2] 3d ea [2] 7a e8 [2] 3d f9 [2] 73 f5 [2] 7f ff [2] 68 f4 [2] 73 ba [2] 4e }

  condition:
    any of them
}