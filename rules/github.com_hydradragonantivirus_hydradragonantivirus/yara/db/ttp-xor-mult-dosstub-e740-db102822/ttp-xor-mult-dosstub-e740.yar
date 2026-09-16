rule TTP_XOR_MULT_DOSStub_e740 {
  strings:
    $key_e740 = { b3 28 [2] c7 30 [2] 80 32 [2] c7 23 [2] 89 2f [2] 85 25 [2] 92 2e [2] 89 60 [2] b4 }

  condition:
    any of them
}