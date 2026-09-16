rule TTP_XOR_MULT_DOSStub_679b {
  strings:
    $key_679b = { 33 f3 [2] 47 eb [2] 00 e9 [2] 47 f8 [2] 09 f4 [2] 05 fe [2] 12 f5 [2] 09 bb [2] 34 }

  condition:
    any of them
}