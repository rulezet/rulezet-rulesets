rule TTP_XOR_MULT_DOSStub_cf8b {
  strings:
    $key_cf8b = { 9b e3 [2] ef fb [2] a8 f9 [2] ef e8 [2] a1 e4 [2] ad ee [2] ba e5 [2] a1 ab [2] 9c }

  condition:
    any of them
}