rule TTP_XOR_MULT_DOSStub_029b {
  strings:
    $key_029b = { 56 f3 [2] 22 eb [2] 65 e9 [2] 22 f8 [2] 6c f4 [2] 60 fe [2] 77 f5 [2] 6c bb [2] 51 }

  condition:
    any of them
}