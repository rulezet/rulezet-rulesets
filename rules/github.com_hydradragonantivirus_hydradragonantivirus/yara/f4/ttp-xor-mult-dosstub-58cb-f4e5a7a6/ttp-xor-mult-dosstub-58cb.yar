rule TTP_XOR_MULT_DOSStub_58cb {
  strings:
    $key_58cb = { 0c a3 [2] 78 bb [2] 3f b9 [2] 78 a8 [2] 36 a4 [2] 3a ae [2] 2d a5 [2] 36 eb [2] 0b }

  condition:
    any of them
}