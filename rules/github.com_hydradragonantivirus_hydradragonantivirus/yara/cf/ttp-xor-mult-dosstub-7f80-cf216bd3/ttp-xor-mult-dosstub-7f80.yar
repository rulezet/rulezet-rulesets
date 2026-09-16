rule TTP_XOR_MULT_DOSStub_7f80 {
  strings:
    $key_7f80 = { 2b e8 [2] 5f f0 [2] 18 f2 [2] 5f e3 [2] 11 ef [2] 1d e5 [2] 0a ee [2] 11 a0 [2] 2c }

  condition:
    any of them
}