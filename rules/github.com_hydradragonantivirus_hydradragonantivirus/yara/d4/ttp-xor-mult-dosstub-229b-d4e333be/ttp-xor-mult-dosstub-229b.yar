rule TTP_XOR_MULT_DOSStub_229b {
  strings:
    $key_229b = { 76 f3 [2] 02 eb [2] 45 e9 [2] 02 f8 [2] 4c f4 [2] 40 fe [2] 57 f5 [2] 4c bb [2] 71 }

  condition:
    any of them
}