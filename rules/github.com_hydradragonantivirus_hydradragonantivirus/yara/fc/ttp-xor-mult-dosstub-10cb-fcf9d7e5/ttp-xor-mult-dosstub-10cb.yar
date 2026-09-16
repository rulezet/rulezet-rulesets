rule TTP_XOR_MULT_DOSStub_10cb {
  strings:
    $key_10cb = { 44 a3 [2] 30 bb [2] 77 b9 [2] 30 a8 [2] 7e a4 [2] 72 ae [2] 65 a5 [2] 7e eb [2] 43 }

  condition:
    any of them
}