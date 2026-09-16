rule TTP_XOR_MULT_DOSStub_1d95 {
  strings:
    $key_1d95 = { 49 fd [2] 3d e5 [2] 7a e7 [2] 3d f6 [2] 73 fa [2] 7f f0 [2] 68 fb [2] 73 b5 [2] 4e }

  condition:
    any of them
}