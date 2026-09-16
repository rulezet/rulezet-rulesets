rule TTP_XOR_MULT_DOSStub_35cb {
  strings:
    $key_35cb = { 61 a3 [2] 15 bb [2] 52 b9 [2] 15 a8 [2] 5b a4 [2] 57 ae [2] 40 a5 [2] 5b eb [2] 66 }

  condition:
    any of them
}