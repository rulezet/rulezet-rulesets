rule TTP_XOR_MULT_DOSStub_71cb {
  strings:
    $key_71cb = { 25 a3 [2] 51 bb [2] 16 b9 [2] 51 a8 [2] 1f a4 [2] 13 ae [2] 04 a5 [2] 1f eb [2] 22 }

  condition:
    any of them
}