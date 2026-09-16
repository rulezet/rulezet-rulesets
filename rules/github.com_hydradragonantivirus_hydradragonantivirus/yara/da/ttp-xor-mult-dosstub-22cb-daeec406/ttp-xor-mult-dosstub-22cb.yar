rule TTP_XOR_MULT_DOSStub_22cb {
  strings:
    $key_22cb = { 76 a3 [2] 02 bb [2] 45 b9 [2] 02 a8 [2] 4c a4 [2] 40 ae [2] 57 a5 [2] 4c eb [2] 71 }

  condition:
    any of them
}