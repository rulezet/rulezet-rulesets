rule TTP_XOR_MULT_DOSStub_5f80 {
  strings:
    $key_5f80 = { 0b e8 [2] 7f f0 [2] 38 f2 [2] 7f e3 [2] 31 ef [2] 3d e5 [2] 2a ee [2] 31 a0 [2] 0c }

  condition:
    any of them
}