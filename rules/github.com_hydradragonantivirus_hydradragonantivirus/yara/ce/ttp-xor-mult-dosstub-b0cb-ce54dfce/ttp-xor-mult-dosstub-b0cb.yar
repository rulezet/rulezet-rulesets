rule TTP_XOR_MULT_DOSStub_b0cb {
  strings:
    $key_b0cb = { e4 a3 [2] 90 bb [2] d7 b9 [2] 90 a8 [2] de a4 [2] d2 ae [2] c5 a5 [2] de eb [2] e3 }

  condition:
    any of them
}