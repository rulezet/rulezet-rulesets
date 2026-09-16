rule TTP_XOR_MULT_DOSStub_e070 {
  strings:
    $key_e070 = { b4 18 [2] c0 00 [2] 87 02 [2] c0 13 [2] 8e 1f [2] 82 15 [2] 95 1e [2] 8e 50 [2] b3 }

  condition:
    any of them
}