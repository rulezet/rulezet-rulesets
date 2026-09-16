rule TTP_XOR_MULT_DOSStub_439b {
  strings:
    $key_439b = { 17 f3 [2] 63 eb [2] 24 e9 [2] 63 f8 [2] 2d f4 [2] 21 fe [2] 36 f5 [2] 2d bb [2] 10 }

  condition:
    any of them
}