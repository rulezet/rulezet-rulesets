rule TTP_XOR_MULT_DOSStub_649b {
  strings:
    $key_649b = { 30 f3 [2] 44 eb [2] 03 e9 [2] 44 f8 [2] 0a f4 [2] 06 fe [2] 11 f5 [2] 0a bb [2] 37 }

  condition:
    any of them
}