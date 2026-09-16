rule TTP_XOR_MULT_DOSStub_15cb {
  strings:
    $key_15cb = { 41 a3 [2] 35 bb [2] 72 b9 [2] 35 a8 [2] 7b a4 [2] 77 ae [2] 60 a5 [2] 7b eb [2] 46 }

  condition:
    any of them
}