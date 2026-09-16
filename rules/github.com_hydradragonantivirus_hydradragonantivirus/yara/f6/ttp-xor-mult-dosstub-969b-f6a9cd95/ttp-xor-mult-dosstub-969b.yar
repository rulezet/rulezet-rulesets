rule TTP_XOR_MULT_DOSStub_969b {
  strings:
    $key_969b = { c2 f3 [2] b6 eb [2] f1 e9 [2] b6 f8 [2] f8 f4 [2] f4 fe [2] e3 f5 [2] f8 bb [2] c5 }

  condition:
    any of them
}