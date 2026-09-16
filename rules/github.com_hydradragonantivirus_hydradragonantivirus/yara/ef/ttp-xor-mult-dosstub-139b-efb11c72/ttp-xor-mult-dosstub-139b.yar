rule TTP_XOR_MULT_DOSStub_139b {
  strings:
    $key_139b = { 47 f3 [2] 33 eb [2] 74 e9 [2] 33 f8 [2] 7d f4 [2] 71 fe [2] 66 f5 [2] 7d bb [2] 40 }

  condition:
    any of them
}