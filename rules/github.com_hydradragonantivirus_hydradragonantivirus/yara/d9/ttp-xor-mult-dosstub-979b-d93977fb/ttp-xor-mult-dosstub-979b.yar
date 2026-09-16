rule TTP_XOR_MULT_DOSStub_979b {
  strings:
    $key_979b = { c3 f3 [2] b7 eb [2] f0 e9 [2] b7 f8 [2] f9 f4 [2] f5 fe [2] e2 f5 [2] f9 bb [2] c4 }

  condition:
    any of them
}