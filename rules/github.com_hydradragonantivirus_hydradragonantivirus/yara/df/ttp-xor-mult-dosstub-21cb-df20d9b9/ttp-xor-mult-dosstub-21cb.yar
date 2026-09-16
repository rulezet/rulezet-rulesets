rule TTP_XOR_MULT_DOSStub_21cb {
  strings:
    $key_21cb = { 75 a3 [2] 01 bb [2] 46 b9 [2] 01 a8 [2] 4f a4 [2] 43 ae [2] 54 a5 [2] 4f eb [2] 72 }

  condition:
    any of them
}