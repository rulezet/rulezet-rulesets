rule TTP_XOR_MULT_DOSStub_7f91 {
  strings:
    $key_7f91 = { 2b f9 [2] 5f e1 [2] 18 e3 [2] 5f f2 [2] 11 fe [2] 1d f4 [2] 0a ff [2] 11 b1 [2] 2c }

  condition:
    any of them
}