rule TTP_XOR_MULT_DOSStub_63cb {
  strings:
    $key_63cb = { 37 a3 [2] 43 bb [2] 04 b9 [2] 43 a8 [2] 0d a4 [2] 01 ae [2] 16 a5 [2] 0d eb [2] 30 }

  condition:
    any of them
}