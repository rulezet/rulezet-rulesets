rule TTP_XOR_MULT_DOSStub_5f86 {
  strings:
    $key_5f86 = { 0b ee [2] 7f f6 [2] 38 f4 [2] 7f e5 [2] 31 e9 [2] 3d e3 [2] 2a e8 [2] 31 a6 [2] 0c }

  condition:
    any of them
}