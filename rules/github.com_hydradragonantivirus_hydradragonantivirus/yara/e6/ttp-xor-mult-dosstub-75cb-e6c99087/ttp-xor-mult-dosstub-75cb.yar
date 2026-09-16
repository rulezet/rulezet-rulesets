rule TTP_XOR_MULT_DOSStub_75cb {
  strings:
    $key_75cb = { 21 a3 [2] 55 bb [2] 12 b9 [2] 55 a8 [2] 1b a4 [2] 17 ae [2] 00 a5 [2] 1b eb [2] 26 }

  condition:
    any of them
}