rule TTP_XOR_MULT_DOSStub_a89b {
  strings:
    $key_a89b = { fc f3 [2] 88 eb [2] cf e9 [2] 88 f8 [2] c6 f4 [2] ca fe [2] dd f5 [2] c6 bb [2] fb }

  condition:
    any of them
}