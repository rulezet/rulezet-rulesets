rule TTP_XOR_MULT_DOSStub_4980 {
  strings:
    $key_4980 = { 1d e8 [2] 69 f0 [2] 2e f2 [2] 69 e3 [2] 27 ef [2] 2b e5 [2] 3c ee [2] 27 a0 [2] 1a }

  condition:
    any of them
}