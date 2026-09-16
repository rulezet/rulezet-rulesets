rule TTP_XOR_MULT_DOSStub_3f81 {
  strings:
    $key_3f81 = { 6b e9 [2] 1f f1 [2] 58 f3 [2] 1f e2 [2] 51 ee [2] 5d e4 [2] 4a ef [2] 51 a1 [2] 6c }

  condition:
    any of them
}