rule TTP_XOR_MULT_DOSStub_45cb {
  strings:
    $key_45cb = { 11 a3 [2] 65 bb [2] 22 b9 [2] 65 a8 [2] 2b a4 [2] 27 ae [2] 30 a5 [2] 2b eb [2] 16 }

  condition:
    any of them
}