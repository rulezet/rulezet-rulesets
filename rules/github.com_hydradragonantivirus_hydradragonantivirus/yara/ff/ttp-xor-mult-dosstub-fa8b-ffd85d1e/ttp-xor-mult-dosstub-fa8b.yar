rule TTP_XOR_MULT_DOSStub_fa8b {
  strings:
    $key_fa8b = { ae e3 [2] da fb [2] 9d f9 [2] da e8 [2] 94 e4 [2] 98 ee [2] 8f e5 [2] 94 ab [2] a9 }

  condition:
    any of them
}