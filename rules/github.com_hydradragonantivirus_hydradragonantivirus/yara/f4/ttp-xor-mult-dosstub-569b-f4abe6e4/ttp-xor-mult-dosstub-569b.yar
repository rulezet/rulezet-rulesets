rule TTP_XOR_MULT_DOSStub_569b {
  strings:
    $key_569b = { 02 f3 [2] 76 eb [2] 31 e9 [2] 76 f8 [2] 38 f4 [2] 34 fe [2] 23 f5 [2] 38 bb [2] 05 }

  condition:
    any of them
}