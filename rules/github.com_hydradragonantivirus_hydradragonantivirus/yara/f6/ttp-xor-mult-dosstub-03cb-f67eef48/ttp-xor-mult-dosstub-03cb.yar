rule TTP_XOR_MULT_DOSStub_03cb {
  strings:
    $key_03cb = { 57 a3 [2] 23 bb [2] 64 b9 [2] 23 a8 [2] 6d a4 [2] 61 ae [2] 76 a5 [2] 6d eb [2] 50 }

  condition:
    any of them
}