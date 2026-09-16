rule TTP_XOR_MULT_DOSStub_25cb {
  strings:
    $key_25cb = { 71 a3 [2] 05 bb [2] 42 b9 [2] 05 a8 [2] 4b a4 [2] 47 ae [2] 50 a5 [2] 4b eb [2] 76 }

  condition:
    any of them
}