rule TTP_XOR_MULT_DOSStub_49cb {
  strings:
    $key_49cb = { 1d a3 [2] 69 bb [2] 2e b9 [2] 69 a8 [2] 27 a4 [2] 2b ae [2] 3c a5 [2] 27 eb [2] 1a }

  condition:
    any of them
}