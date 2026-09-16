rule TTP_XOR_MULT_DOSStub_c440 {
  strings:
    $key_c440 = { 90 28 [2] e4 30 [2] a3 32 [2] e4 23 [2] aa 2f [2] a6 25 [2] b1 2e [2] aa 60 [2] 97 }

  condition:
    any of them
}