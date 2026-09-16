rule TTP_XOR_MULT_DOSStub_e770 {
  strings:
    $key_e770 = { b3 18 [2] c7 00 [2] 80 02 [2] c7 13 [2] 89 1f [2] 85 15 [2] 92 1e [2] 89 50 [2] b4 }

  condition:
    any of them
}