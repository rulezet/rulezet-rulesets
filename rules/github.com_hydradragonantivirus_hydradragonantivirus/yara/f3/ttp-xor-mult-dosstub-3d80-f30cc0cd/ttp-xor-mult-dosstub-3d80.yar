rule TTP_XOR_MULT_DOSStub_3d80 {
  strings:
    $key_3d80 = { 69 e8 [2] 1d f0 [2] 5a f2 [2] 1d e3 [2] 53 ef [2] 5f e5 [2] 48 ee [2] 53 a0 [2] 6e }

  condition:
    any of them
}