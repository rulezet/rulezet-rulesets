rule TTP_XOR_MULT_DOSStub_e4cb {
  strings:
    $key_e4cb = { b0 a3 [2] c4 bb [2] 83 b9 [2] c4 a8 [2] 8a a4 [2] 86 ae [2] 91 a5 [2] 8a eb [2] b7 }

  condition:
    any of them
}