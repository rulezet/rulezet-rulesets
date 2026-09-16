rule TTP_XOR_MULT_DOSStub_b6cb {
  strings:
    $key_b6cb = { e2 a3 [2] 96 bb [2] d1 b9 [2] 96 a8 [2] d8 a4 [2] d4 ae [2] c3 a5 [2] d8 eb [2] e5 }

  condition:
    any of them
}