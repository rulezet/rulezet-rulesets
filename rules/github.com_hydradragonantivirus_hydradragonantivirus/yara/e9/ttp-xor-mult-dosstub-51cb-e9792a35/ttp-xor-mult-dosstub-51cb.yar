rule TTP_XOR_MULT_DOSStub_51cb {
  strings:
    $key_51cb = { 05 a3 [2] 71 bb [2] 36 b9 [2] 71 a8 [2] 3f a4 [2] 33 ae [2] 24 a5 [2] 3f eb [2] 02 }

  condition:
    any of them
}