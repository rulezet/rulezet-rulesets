rule TTP_XOR_MULT_DOSStub_4670 {
  strings:
    $key_4670 = { 12 18 [2] 66 00 [2] 21 02 [2] 66 13 [2] 28 1f [2] 24 15 [2] 33 1e [2] 28 50 [2] 15 }

  condition:
    any of them
}