rule TTP_XOR_MULT_DOSStub_23cb {
  strings:
    $key_23cb = { 77 a3 [2] 03 bb [2] 44 b9 [2] 03 a8 [2] 4d a4 [2] 41 ae [2] 56 a5 [2] 4d eb [2] 70 }

  condition:
    any of them
}