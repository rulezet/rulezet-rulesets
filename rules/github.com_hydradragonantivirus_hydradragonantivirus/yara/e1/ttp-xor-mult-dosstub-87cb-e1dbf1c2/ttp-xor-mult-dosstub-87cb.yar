rule TTP_XOR_MULT_DOSStub_87cb {
  strings:
    $key_87cb = { d3 a3 [2] a7 bb [2] e0 b9 [2] a7 a8 [2] e9 a4 [2] e5 ae [2] f2 a5 [2] e9 eb [2] d4 }

  condition:
    any of them
}